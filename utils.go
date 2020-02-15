package cls

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"github.com/mulinbc/zerr"
	"github.com/pierrec/lz4/v3"
)

// AlphabeticCaseInsensitive 用于大小写不敏感的字母序排序。
type AlphabeticCaseInsensitive []string

func (p AlphabeticCaseInsensitive) Len() int {
	return len(p)
}

func (p AlphabeticCaseInsensitive) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p AlphabeticCaseInsensitive) Less(i, j int) bool {
	var si string = p[i]
	var sj string = p[j]
	var siLower = strings.ToLower(si)
	var sjLower = strings.ToLower(sj)
	if siLower == sjLower {
		return si < sj
	}
	return siLower < sjLower
}

// lz4Compress 使用 lz4 算法对数据进行压缩。
// 如果数据不可压缩，则返回 errIncompressible。
func lz4Compress(src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	ht := make([]int, 64<<10) // 哈希表大小至少为 64 Kb

	n, err := lz4.CompressBlock(src, dst, ht)
	if err != nil {
		return nil, zerr.Wrap(err)
	}
	if n == 0 || n >= len(src) {
		return nil, zerr.Wrap(errIncompressible)
	}
	return dst[:n], nil
}

func md5Sum(p []byte) string {
	h := md5.New()
	h.Write(p)
	return hex.EncodeToString(h.Sum(nil))
}

func sha1Sum(p []byte) string {
	h := sha1.New()
	h.Write(p)
	return hex.EncodeToString(h.Sum(nil))
}

func hmacSha1(p, key []byte) string {
	mac := hmac.New(sha1.New, key)
	mac.Write(p)
	return hex.EncodeToString(mac.Sum(nil))
}
