# Go-SharedSecret - Helpful library for sharing a secret (WIP)

[![Build Status](https://travis-ci.org/AlekNS/go-sharedsecret.svg?branch=master)](https://travis-ci.org/AlekNS/go-sharedsecret)
[![Go Report Card](https://goreportcard.com/badge/github.com/AlekNS/go-sharedsecret)](https://goreportcard.com/report/github.com/AlekNS/go-sharedsecret)

Adapted Shamir's algorithm from the [js implementation](https://github.com/grempe/secrets.js)

## Installation

#### Go get

```
go get github.com/alekns/go-sharedsecret
```

#### Features

## Examples

### Shamir Share

secCtx := SecurityContext{8, 16, 128}
svc := NewShareSecretByShamirSchema(NewShamirFullSecretFormatter(secCtx))
parts, err := svc.Share("12345678", 3, 2, 128)

// parts - slice of hex strings

### Share secret with transformation

// forward

p1 := PipeTransform(
    InvertTransform(HexTransform()),
    TransformEncryptAES("user1SecretKey"),
    Base64Transform())

p2 := PipeTransform(
    InvertTransform(HexTransform()),
    TransformEncryptAES("server1SecretKey"),
    HexTransform())

p3 := PipeTransform(
    InvertTransform(HexTransform()),
    TransformEncryptAES("server2SecretKey"),
    TransformEncryptAES("globalkey"),
    Base64Transform())

parts, err := svc.Share("12345678", 3, 2, 128)
values, err := TransformShare(parts, p1, p2, p3)

// backward

shares, err := TransformCombine(parts[:2], p1, p2)
secret, err := svc.Combine(shares, 0)
