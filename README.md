[![Godoc Reference](https://godoc.org/github.com/bingoohuang/sio?status.svg)](https://godoc.org/github.com/bingoohuang/sio)
[![Travis CI](https://travis-ci.org/bingoohuang/sio.svg?branch=master)](https://travis-ci.org/bingoohuang/sio)
[![Go Report Card](https://goreportcard.com/badge/bingoohuang/sio)](https://goreportcard.com/report/bingoohuang/sio)

# Secure IO

## Go implementation of the Data At Rest Encryption (DARE) format.

## Introduction

It is a common problem to store data securely - especially on untrusted remote storage. One solution to this problem is
cryptography. Before data is stored it is encrypted to ensure that the data is confidential. Unfortunately encrypting
data is not enough to prevent more sophisticated attacks. Anyone who has access to the stored data can try to manipulate
the data - even if the data is encrypted.

安全地存储数据是一个常见的问题，尤其是在不受信任的远程存储上。这个问题的一个解决方案是密码学。在数据被存储之前，它被加密以确保数据的机密性。
不幸的是，加密数据不足以防止更复杂的攻击。任何能够访问存储的数据的人都可以尝试操作这些数据——即使这些数据是加密的。

To prevent these kinds of attacks the data must be encrypted in a tamper-resistant way. This means an attacker should
not be able to:
为了防止这类攻击，必须以防篡改的方式对数据进行加密。这意味着攻击者不能:

- Read the stored data - this is achieved by modern encryption algorithms. 读取存储的数据——这是通过现代加密算法实现的。
- Modify the data by changing parts of the encrypted data. 通过更改部分加密数据来修改数据。
- Rearrange or reorder parts of the encrypted data. 重新排列或重新排序部分加密数据。

Authenticated encryption schemes (AE) - like AES-GCM or ChaCha20-Poly1305 - encrypt and authenticate data. Any
modification to the encrypted data (ciphertext) is detected while decrypting the data. But even an AE scheme alone is
not sufficiently enough to prevent all kinds of data manipulation.

认证加密方案(AE)——如 AES-GCM 或 ChaCha20-Poly1305——加密和认证数据。 在解密数据时检测到对加密数据(密文)的任何修改。但是即使是一个 AE 方案本身也不足以防止所有类型的数据操作。

All modern AE schemes produce an authentication tag which is verified after the ciphertext is decrypted. If a large
amount of data is decrypted it is not always possible to buffer all decrypted data until the authentication tag is
verified. Returning unauthenticated data has the same issues as encrypting data without authentication.

所有现代的 AE 方案都会产生一个验证标签，在解密后验证。如果大量数据被解密，那么在验证标记被验证之前， 并不总是可以缓冲所有解密的数据。返回未经身份验证的数据具有相同的问题，比如不经身份验证就对数据进行加密。

Splitting the data into small chunks fixes the problem of deferred authentication checks but introduces a new one. The
chunks can be reordered - e.g. exchanging chunk 1 and 2 - because every chunk is encrypted separately. Therefore, the
order of the chunks must be encoded somehow into the chunks itself to be able to detect rearranging any number of
chunks.

将数据分割成小块解决了延迟认证检查的问题，但引入了一个新的认证检查。 块可以重新排序——例如交换块1和块2——因为每个块都是分开加密的。因此，块的顺序必须以某种方式编码到块本身中，以便能够检测重新安排任意数量的块。

This project specifies a [format](https://github.com/bingoohuang/sio/blob/master/DARE.md) for en/decrypting an arbitrary
data stream and gives some [recommendations](https://github.com/bingoohuang/sio/blob/master/DARE.md#appendices)
about how to use and implement data at rest encryption (DARE). Additionally, this project provides a reference
implementation in Go.

该项目指定了一种格式，用于对任意数据流进行编解密，并对如何使用和实现静止加密(DARE)提出了一些建议。此外，该项目还提供了 Go 中的参考实现。

## Applications

DARE is designed with simplicity and efficiency in mind. It combines modern AE schemes with a very simple reorder
protection mechanism to build a tamper-resistant encryption scheme. DARE can be used to encrypt files, backups and even
large object storage systems.

设计的目的是简单和效率。它将现代 AE 方案与非常简单的重排序保护机制相结合，构建了一个抗篡改加密方案。DARE 可用于加密文件，备份，甚至大型对象存储系统。

Its main properties are:

- Security and high performance by relying on modern AEAD ciphers 安全性和高性能依赖于现代 AEAD 密码
- Small overhead - encryption increases the amount of data by ~0.05% 较小的开销 - 加密增加了约0.05% 的数据量
- Support for long data streams - up to 256 TB under the same key 支持长数据流——在同一个键下最高可达256TB
- Random access - arbitrary sequences / ranges can be decrypted independently 随机存取-任意序列/范围可以独立解密

**Install:** `go get -u github.com/bingoohuang/sio`

DARE and `github.com/bingoohuang/sio` are finalized and can be used in production. 可以用于生产。

We also provide a CLI tool to en/decrypt arbitrary data streams directly from your command line:

我们还提供了一个 CLI 工具，可以直接从命令行对任意数据流进行编译/解密:

**Install sio:** `go install github.com/bingoohuang/sio/cmd/sio && sio -h`

## Performance

Cipher            |   8 KB   |   64 KB   |   512 KB  |  1 MB
----------------- | -------- | --------- | --------- | --------
AES_256_GCM       |  90 MB/s | 1.96 GB/s | 2.64 GB/s | 2.83 GB/s
CHACHA20_POLY1305 |  97 MB/s | 1.23 GB/s | 1.54 GB/s | 1.57 GB/s

*On i7-6500U 2 x 2.5 GHz | Linux 4.10.0-32-generic | Go 1.8.3 | AES-NI & AVX2*
