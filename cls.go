// Package cls provides simple API for CLS.
package cls

import (
	"bytes"
	"context"
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
	Host          string        `validate:"fqdn"`
	SignAlgorithm string        `validate:"oneof=sha1"`
	CompressType  string        `validate:"oneof=lz4"`
	Expire        time.Duration `validate:"required"`

	validate *validator.Validate
	client   *http.Client
	common   service

	Log *LogService
}

type service struct {
	client *Client
}

// SearchReq 表示 CLS 搜索日志 API 请求参数。
type SearchReq struct {
	LogSetID  string    `validate:"required"`
	TopicIDs  []string  `validate:"required"`
	StartTime time.Time `validate:"required"`
	EndTime   time.Time `validate:"required"`
	Query     string    `validate:"omitempty"`
	Limit     int       `validate:"min=1,max=100"`
	Context   string    `validate:"omitempty"`
	Sort      string    `validate:"omitempty,oneof=asc desc"`
}

// SearchResp 表示 CLS 搜索日志 API 响应参数。
type SearchResp struct {
	Context   string      `json:"context"`
	Listover  bool        `json:"listover"`
	Results   []LogObject `json:"results"`
	SQLFlag   bool        `json:"sql_flag"`
	RequestID string      `json:"-"`
	Error     *ErrorInfo  `json:"-"`
}

// LogObject 表示日志内容信息。
type LogObject struct {
	Content   string `json:"content"`
	Filename  string `json:"filename"`
	Source    string `json:"source"`
	Timestamp string `json:"timestamp"`
	TopicID   string `json:"topic_id"`
	TopicName string `json:"topic_name"`
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
		validate:      validator.New(),
	}

	c.client = httpClient
	c.common.client = c

	c.Log = (*LogService)(&c.common)

	if err := c.validate.Struct(c); err != nil {
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

// Search 用于搜索日志，单次返回的最大条数为100。
func (p *LogService) Search(searchReq SearchReq) (SearchResp, error) {
	resp, err := p.SearchWithContext(context.Background(), searchReq)
	if err != nil {
		return SearchResp{}, zerr.Wrap(err)
	}

	return resp, nil
}

// SearchWithContext 用于搜索日志，通过 context 控制生命周期，单次返回的最大条数为100。
func (p *LogService) SearchWithContext(ctx context.Context, searchReq SearchReq) (SearchResp, error) {
	if err := p.client.validate.Struct(searchReq); err != nil {
		return SearchResp{}, zerr.Wrap(err)
	}

	resp, err := p.searchWithContext(ctx, searchReq)
	if err != nil {
		return SearchResp{}, zerr.Wrap(err)
	}

	return resp, nil
}

// SearchAll 用于搜索日志，最多 10000 条。
func (p *LogService) SearchAll(ctx context.Context, w io.Writer, searchReq SearchReq) ([]string, error) {
	requestIDs := make([]string, 0)
	contextTemp := searchReq.Context
	limitTemp := 0
	cnt := 0

	for {
		select {
		case <-ctx.Done():
			return nil, zerr.Wrap(fmt.Errorf("context canceled"))
		default:
			if searchReq.Limit-cnt >= 100 {
				limitTemp = 100
			} else {
				limitTemp = searchReq.Limit - cnt
			}
			searchResp, err := p.searchWithContext(ctx, SearchReq{searchReq.LogSetID, searchReq.TopicIDs, searchReq.StartTime, searchReq.EndTime, searchReq.Query, limitTemp, contextTemp, searchReq.Sort})
			requestIDs = append(requestIDs, searchResp.RequestID)
			if err != nil {
				return requestIDs, zerr.Wrap(err)
			}
			contextTemp = searchResp.Context

			for _, r := range searchResp.Results {
				// CLS 接口返回数据不一致，无换行时添加换行符('\n')！！
				c := r.Content
				if !strings.HasSuffix(c, "\n") {
					c = c + "\n"
				}
				_, err := w.Write([]byte(c))
				if err != nil {
					return requestIDs, zerr.Wrap(err)
				}
				cnt++
				if cnt >= searchReq.Limit {
					return requestIDs, nil
				}
			}
			if searchResp.Listover {
				return requestIDs, nil
			}
		}
	}
}

func (p *LogService) searchWithContext(ctx context.Context, searchReq SearchReq) (SearchResp, error) {
	searchResp := SearchResp{}

	v := url.Values{}
	v.Set("logset_id", searchReq.LogSetID)
	v.Set("topic_ids", strings.Join(searchReq.TopicIDs, ","))
	v.Set("start_time", searchReq.StartTime.Format(timeLayout))
	v.Set("end_time", searchReq.EndTime.Format(timeLayout))
	v.Set("query_string", searchReq.Query)
	v.Set("limit", strconv.Itoa(searchReq.Limit))
	if searchReq.Context != "" {
		v.Set("context", searchReq.Context)
	}
	if searchReq.Sort != "" {
		v.Set("sort", searchReq.Sort)
	}
	u := url.URL{
		Scheme:   p.client.Scheme,
		Host:     p.client.Host,
		Path:     "searchlog",
		RawQuery: v.Encode(),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return searchResp, zerr.Wrap(err)
	}
	req.Header.Set("Host", p.client.Host)
	req.Header.Set("Content-Type", "application/x-protobuf")
	authorization := p.client.genAuthorization(time.Now(), p.client.Expire, req)
	req.Header.Set("Authorization", authorization)

	resp, err := p.client.client.Do(req)
	if err != nil {
		return searchResp, zerr.Wrap(err)
	}
	defer resp.Body.Close()

	searchResp.RequestID = resp.Header.Get("x-cls-requestid")
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return searchResp, zerr.Wrap(err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		errorInfo := &ErrorInfo{}
		if err := json.Unmarshal(b, errorInfo); err != nil {
			return searchResp, zerr.Wrap(err)
		}
		searchResp.Error = errorInfo
		return searchResp, zerr.Wrap(fmt.Errorf("search failed, status code is %d, error code is \"%s\", error message is \"%s\"", resp.StatusCode, errorInfo.ErrorCode, errorInfo.ErrorMessage))
	}

	if err := json.Unmarshal(b, &searchResp); err != nil {
		return searchResp, zerr.Wrap(err)
	}

	return searchResp, nil
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
