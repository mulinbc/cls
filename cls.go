// Package cls provides simple API for CLS.
package cls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang/protobuf/proto"
	"github.com/mulinbc/zerr"
)

// LogService 表示日志管理相关 API。
type LogService service

// Client 表示与 CLS API 通信所需的数据结构。
type Client struct {
	SecretID      string        `validate:"required"`
	SecretKey     string        `validate:"required"`
	Scheme        string        `validate:"oneof=http https"`
	Host          string        `validate:"hostname"`
	SignAlgorithm string        `validate:"oneof=sha1"`
	CompressType  string        `validate:"oneof=lz4"`
	Expire        time.Duration `validate:"required"`

	client *http.Client
	common service

	Log *LogService
}

type service struct {
	client *Client
}

// SearchResponse 表示 CLS 搜索日志 API 响应信息。
type SearchResponse struct {
	Context  string      `json:"context"`
	Listover bool        `json:"listover"`
	Results  []LogObject `json:"results"`
	SQLFlag  bool        `json:"sql_flag"`
}

// LogObject 表示日志内容信息。
type LogObject struct {
	TopicID   string `json:"topic_id"`
	TopicName string `json:"topic_name"`
	Timestamp string `json:"timestamp"`
	Content   string `json:"content"`
	Filename  string `json:"filename"`
	Source    string `json:"source"`
}

// ErrorInfo 表示 CLS API 返回的错误信息。
type ErrorInfo struct {
	ErrorCode    string `json:"errorcode"`
	ErrorMessage string `json:"errormessage"`
}

// NewClient 返回调用 CLS API 的客户端。
func NewClient(httpClient *http.Client, secretID, secretKey, scheme, host, signAlgorithm, compressType string, expire time.Duration) (*Client, error) {
	c := &Client{
		SecretID:      secretID,
		SecretKey:     secretKey,
		Scheme:        scheme,
		Host:          host,
		SignAlgorithm: signAlgorithm,
		CompressType:  compressType,
		Expire:        expire,
	}

	c.client = httpClient
	c.common.client = c

	c.Log = (*LogService)(&c.common)

	if err := validator.New().Struct(c); err != nil {
		return nil, zerr.Wrap(err)
	}

	return c, nil
}

// Upload 用于上传结构化日志。
// 如果 hash 为 true，则使用哈希路由模式，以保证数据在该分区上写入和消费是严格保序的。
// https://cloud.tencent.com/document/product/614/39259
func (p *LogService) Upload(topicID string, l *LogGroupList, compress, hash bool) (string, error) {
	// TODO: 校验数量
	// 单条日志 value 不能超过1MB，LogGroup 中所有 value 总和不能超过5MB
	// 一个 LogGroup 中 Log 个数不能超过10000
	// https://cloud.tencent.com/document/product/614/16873

	body := bytes.NewBuffer(nil)
	incompressible := false

	pb, err := proto.Marshal(l)
	if err != nil {
		return "", zerr.Wrap(err)
	}

	if compress {
		dst, err := lz4Compress(pb)
		if err != nil {
			if !errors.Is(err, errIncompressible) {
				return "", zerr.Wrap(err)
			}
			body.Write(pb)
			incompressible = true
		} else {
			body.Write(dst)
		}
	} else {
		body.Write(pb)
	}

	q := url.Values{}
	q.Add("topic_id", topicID)
	u := url.URL{
		Scheme:   p.client.Scheme,
		Host:     p.client.Host,
		Path:     "structuredlog",
		RawQuery: q.Encode(),
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), body)
	if err != nil {
		return "", zerr.Wrap(err)
	}

	req.Header.Set("Host", p.client.Host)
	req.Header.Set("Content-Type", "application/x-protobuf")
	if compress && !incompressible {
		req.Header.Set("x-cls-compress-type", p.client.CompressType)
	}
	if hash {
		req.Header.Set("x-cls-hashkey", md5Sum(body.Bytes()))
	}

	authorization := p.client.genAuthorization(time.Now(), p.client.Expire, req)
	req.Header.Set("Authorization", authorization)

	resp, err := p.client.client.Do(req)
	if err != nil {
		return "", zerr.Wrap(err)
	}
	defer resp.Body.Close()

	requestID := resp.Header.Get("x-cls-requestid")

	if resp.StatusCode >= http.StatusBadRequest {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return requestID, zerr.Wrap(err)
		}

		e := ErrorInfo{}
		if err := json.Unmarshal(b, &e); err != nil {
			return requestID, zerr.Wrap(err)
		}

		return requestID, zerr.Wrap(fmt.Errorf("%s: %s", e.ErrorCode, e.ErrorMessage))
	}

	return requestID, nil
}

// Search 用于搜索日志，最多 10000 条。
func (p *LogService) Search(w io.Writer, logsetID string, topicIDs []string, startTime, endTime time.Time, query string, limit int, context string, desc bool) ([]string, error) {
	requestIDs := make([]string, 0)

	contextTemp := context
	sort := "desc"
	if !desc {
		sort = "asc"
	}

	for {
		requestID, searchResp, err := p.search(logsetID, topicIDs, startTime, endTime, query, limit, contextTemp, sort)
		requestIDs = append(requestIDs, requestID)
		if err != nil {
			return requestIDs, zerr.Wrap(err)
		}

		contextTemp = searchResp.Context

		for _, r := range searchResp.Results {
			_, err := w.Write([]byte(r.Content))
			if err != nil {
				return requestIDs, zerr.Wrap(err)
			}
		}
		if searchResp.Listover {
			break
		}
	}

	return requestIDs, nil
}

func (p *LogService) search(logsetID string, topicIDs []string, startTime, endTime time.Time, query string, limit int, context, sort string) (string, SearchResponse, error) {
	searchResp := SearchResponse{}

	q := url.Values{}
	q.Add("logset_id", logsetID)
	q.Add("topic_ids", strings.Join(topicIDs, ","))
	q.Add("start_time", startTime.Format(timeLayout))
	q.Add("end_time", endTime.Format(timeLayout))
	q.Add("query", query)
	q.Add("limit", strconv.Itoa(limit))
	q.Add("context", context)
	q.Add("sort", sort)
	u := url.URL{
		Scheme:   p.client.Scheme,
		Host:     p.client.Host,
		Path:     "searchlog",
		RawQuery: q.Encode(),
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", searchResp, zerr.Wrap(err)
	}
	req.Header.Set("Host", p.client.Host)
	req.Header.Set("Content-Type", "application/x-protobuf")
	authorization := p.client.genAuthorization(time.Now(), p.client.Expire, req)
	req.Header.Set("Authorization", authorization)

	resp, err := p.client.client.Do(req)
	if err != nil {
		return "", searchResp, zerr.Wrap(err)
	}
	defer resp.Body.Close()

	requestID := resp.Header.Get("x-cls-requestid")

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return requestID, searchResp, zerr.Wrap(err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		e := ErrorInfo{}
		if err := json.Unmarshal(b, &e); err != nil {
			return requestID, searchResp, zerr.Wrap(err)
		}
		return requestID, searchResp, zerr.Wrap(fmt.Errorf("%s: %s", e.ErrorCode, e.ErrorMessage))
	}

	if err := json.Unmarshal(b, &searchResp); err != nil {
		return requestID, searchResp, zerr.Wrap(err)
	}

	return requestID, searchResp, nil
}

// genAuthorization 用于生成请求签名。
func (p *Client) genAuthorization(start time.Time, expire time.Duration, req *http.Request) string {
	auth := strings.Builder{}
	sep := "&"

	auth.WriteString("q-sign-algorithm=")
	auth.WriteString(p.SignAlgorithm)
	auth.WriteString(sep)

	auth.WriteString("q-ak=")
	auth.WriteString(p.SecretID)
	auth.WriteString(sep)

	auth.WriteString("q-sign-time=")
	qSignTime := strconv.FormatInt(start.Unix(), 10) + ";" + strconv.FormatInt(start.Add(expire).Unix(), 10)
	auth.WriteString(qSignTime)
	auth.WriteString(sep)

	auth.WriteString("q-key-time=")
	qKeyTime := qSignTime
	auth.WriteString(qKeyTime)
	auth.WriteString(sep)

	auth.WriteString("q-header-list=")
	formatedHeaders, signedHeaderList := genFormatedHeaders(req.Header)
	auth.WriteString(signedHeaderList)
	auth.WriteString(sep)

	auth.WriteString("q-url-param-list=")
	formatedParameters, signedParamList := genFormatedParameters(req.URL.Query())
	auth.WriteString(signedParamList)
	auth.WriteString(sep)

	auth.WriteString("q-signature=")

	httpRequestInfo := strings.ToLower(req.Method) + "\n" +
		req.URL.Path + "\n" +
		formatedParameters + "\n" +
		formatedHeaders + "\n"
	stringToSign := p.SignAlgorithm + "\n" +
		qSignTime + "\n" +
		sha1Sum([]byte(httpRequestInfo)) + "\n"
	signKey := hmacSha1([]byte(qKeyTime), []byte(p.SecretKey))
	signature := hmacSha1([]byte(stringToSign), []byte(signKey))
	auth.WriteString(signature)

	return auth.String()
}

// genFormatedParameters 用于生成 formatedParameters 和 signedParamList。
func genFormatedParameters(query url.Values) (string, string) {
	n := len(query)
	fps := strings.Builder{}
	spl := strings.Builder{}

	qks := make(AlphabeticCaseInsensitive, 0, n)
	for k := range query {
		qks = append(qks, k)
	}
	sort.Sort(qks)

	for i, k := range qks {
		lk := strings.ToLower(k)
		spl.WriteString(lk)

		fps.WriteString(lk)
		fps.WriteString("=")
		fps.WriteString(url.QueryEscape(query.Get(k)))

		if i < n-1 {
			fps.WriteString("&")
			spl.WriteString(";")
		}
	}
	return fps.String(), spl.String()
}

// genFormatedHeaders 用于生成 formatedHeaders 和 signedHeaderList。
func genFormatedHeaders(headers http.Header) (string, string) {
	n := len(headers)
	fhs := strings.Builder{}
	shl := strings.Builder{}

	hks := make(AlphabeticCaseInsensitive, 0, n)
	for k := range headers {
		hks = append(hks, k)
	}
	sort.Sort(hks)

	for i, k := range hks {
		lk := strings.ToLower(k)
		shl.WriteString(lk)

		fhs.WriteString(lk)
		fhs.WriteString("=")
		fhs.WriteString(url.QueryEscape(headers.Get(k)))

		if i < n-1 {
			fhs.WriteString("&")
			shl.WriteString(";")
		}
	}
	return fhs.String(), shl.String()
}
