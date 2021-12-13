+++
title = "libbpf-rsを使ってeBPFプログラミングに入門する"
date = 2021-08-22
[taxonomies]
tags = ["wip","linux","ebpf"]
+++

## はじめに
この記事ではeBPFを活用してLinuxカーネルにフック用プログラムを注入することにより、ネットワークパケット処理を拡張する例を示します。
またその実装にあたり、Rustとlibbpfの統合を行うlibbpf-rsを使った開発体験を記したいと思います。

## eBPF
TODO:
カーネル内部のイベントをトリガとして呼び出されるプログラムをユーザ空間から注入できる機能です。
専用のバイトコードをカーネル内の仮想マシンに解釈させることで命令を実行します。

eBPFの拡張性を活用したCiliumがGKEの新たなコンテナネットワーキングの実装に選ばれた実績を見ると、それなりに注目度が高いことが伺えます。

[コンテナのセキュリティと可視性が強化された GKE Dataplane V2 が登場](https://cloud.google.com/blog/ja/products/containers-kubernetes/bringing-ebpf-and-cilium-to-google-kubernetes-engine)

## TL;DR
libbpf-rsによってコンパイルやロード処理の手間は省けるようになるのは良いのですが、本当に苦労するのは以下です。

- デバッグとトラブルシュートとテスト
- 利用したいeBPF機能が入っているカーネル/ディストリビューションを用意する

## 課題設定
サーバ上のTCP 8080ポートに対する通信をTCP 8081ポートでlistenしているプロセスへとリダイレクトします。
これをeBPFを使ったパケット処理に拡張機能であるXDP(eXpress Data Path)で実装します。

とても現実にありえる正気のユースケースとは思えませんが、頑張ればいつか

## eBPFプログラミングの登場人物
eBPFプログラムはカーネル空間側で実行されますが、実用上はそのeBPFプログラムをカーネルにロードしたり、実行結果を取り出すためにユーザ空間側で動作するプログラムも必要となります。
カーネル空間、ユーザ空間2種類のプログラムをビルドして配布しつつ、それぞれのプログラムごとにビルドツールが分かれがちなので、とっかかりで混乱します。

- clang/llvm
    - カーネル空間のコードを(制限された)C言語で記述しeBPFバイトコードへとコンパイルするために必要
- libbpfとその依存関係
    - カーネルが提供するeBPFシステムコールをラップするAPIやユーティリティを提供するライブラリ
- eBPFプログラム
    - カーネル空間側で動作するバイトコード
- アプリケーションプログラム (ユーザ側)
    - ユーザ空間側で動作し、eBPFプログラムをロードしたり実行結果を取り出したりするアプリケーション

今回はアプリケーションプログラム側としてRustを選択し、libbpf-rs crateが提供するワークフローによって少しでも開発の手間をなくせるか実際に試してみます。

### eBPFプログラミングの流れ
一般的には下記のようなステップを踏みます。

1. カーネルで動作するeBPF用のC言語のプログラムを書く
2. clang/llvmでコンパイルしeBPFのバイトコードを生成する(ELF形式)
3. eBPFバイトコードをカーネルにロードするユーザ空間側のプログラムを書く
4. 3をコンパイルし2の結果と合わせて利用する

libbpf-rsを使ってRustベースの開発を行う場合は以下のｍようになります。

1. カーネルで動作するeBPF用のC言語のプログラムを書く
2. eBPFバイトコードをカーネルにロードするユーザ空間側のプログラムを *Rust* で書く
3. cargo buildで1, 2の成果物がバンドルされる

libbpf-rsというライブラリが提供する道具立てのおかげで **少し開発ステップが短縮できる** というのがポイントです。

## libbpf-rs
[libbpf-rs](https://github.com/libbpf/libbpf-rs/)

RustのプログラムからeBPFのシステムコールおよびeBPF関連オブジェクトを取り扱いやすくしてくれるライブラリです。
実体としてはlibbpfのRust用ラッパーですが、ただ関数シグニチャをRust側にポーティングしているだけではなく、Rustプログラミングと親和性が高くなるような仕掛けが追加されています。

### libbpfはstaticにリンクする
これはlibbpf-rsそのものの効用というよりは依存する[libbpf-sys](https://github.com/libbpf/libbpf-sys)のおかげですが、[Building](https://github.com/libbpf/libbpf-sys#building)で説明されている通り、libbpfのライブラリがcargo buildの成果物に静的にリンクされるため実行環境でlibbpfをインストールしておく必要がありません。

### eBPFのプログラムの周辺操作を行うスケルトンを自動生成する


## eBPFプログラミング環境のセットアップ

[Building BPF applications with libbpf-bootstrap](https://nakryiko.com/posts/libbpf-bootstrap/)

libbpfの依存関係をインストールしておく
https://github.com/libbpf/libbpf-sys#building

### Cargo.tomlの追記
依存関係として`libbpf-rs`を追加しておきます。`cargo build`でeBPFプログラムのコンパイルも起動するためには、ビルドスクリプトの依存関係として`libbpf-cargo`も追加しておきます。
```
[dependencies]
libbpf-rs = "0.14.0"
libc = "0.2"

[build-dependencies]
libbpf-cargo = "0.9"
```
### `src/bpf/c` を作る
`libbpf-rs`公式だと`src/bpf`にeBPF用のCのコードを`.bpf.c`拡張子で保存することが最初に紹介されますが、
```
mkdir src/bpf/c
```

gitignore
```
src/bpf/*.rs
```

`.bpf.c` ファイルを作る
```
touch src/bpf/tcpconnect.bpf.c
```
ビルドする
```
cargo libbpf make
```

### cargo-libbpf
cargo-libbpfはeBPFプログラムのコンパイルやRustへのインテグレーションをおこなうワークフローを自動化するためのcargo用ライブラリです。
https://docs.rs/libbpf-cargo/latest/libbpf_cargo/#build

上記にあるように
```
cargo libbpf make
```
などでcargoコマンド経由でclangを呼び出すことができます。
しかし普通にRustプログラムを書いていてcargo libbpf makeも忘れずに実行するのは普通にめんどくさいです。

幸いにしてビルドスクリプトから呼び出すことができるAPIがcargo-libbpfにもあるのでこれを使ってcargo build時に合わせてeBPFプログラムもビルドできるようにします。

公式にも下記のようにあるので、むしろそちらが正攻法のようです。

> The build script interface is recommended over the cargo subcommand interface because:

https://docs.rs/libbpf-cargo/latest/libbpf_cargo/#

### ビルドスクリプトを用意する


成果物を確認する
```
 % ls -l target/bpf/tcpconnect.bpf.o
-rw-r--r-- 1 ilyaletre ilyaletre 488 Dec 10 10:17 target/bpf/tcpconnect.bpf.o
10:18:12 ilyaletre@workspace:~/projects/bpf-tools-rs *[main] 
 % file target/bpf/tcpconnect.bpf.o 
target/bpf/tcpconnect.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped
```

https://github.com/iovisor/bcc/blob/99bfe8ac0b3f5d0422e47e09abc073425dc22968/tools/tcpconnect.py#L86-L204
をパクッてつくる

### カーネル空間: eBPFプログラムを書く

今回はパケット操作なので `__sk_buff` を操作するのに必要な操作のみに注目します。

https://github.com/libbpf/libbpf/blob/master/src/bpf_helpers.h
https://github.com/libbpf/libbpf/blob/master/src/bpf_helper_defs.h

`bpf_skb_` で始まるヘルパ関数を利用することができます。

https://www.youtube.com/watch?v=ZNtVedFsD-k&t=240s

### ユーザ空間: eBPFプログラムをロードする

## minimalでやっていることのまとめ

本記事の方を見れば詳細まで分かるがざっと説明しておくと下記のようになる。

1. minimal.bfp.cをclang/llvmでeBPFオブジェクトコードにコンパイルする
2. オブジェクトコードを元にbpftoolがスケルトンを生成してオブジェクトのバイナリをスケルトンヘッダに埋め込む
3. ユーザ側プログラムがこのスケルトンをincludeしつつコンパイルされる
4. libbpfと静的リンクされて実行ファイルが作られる

それぞれのステップがlibbpf-rsではどうなるのか確認していく。

## いろいろな課題
### テスト
verifierはあるのでカーネルがクラッシュするようなコードは弾かれるのですが、そうはいっても正しく動くかのテストはしたくなります。
特にeBPFでカバーする層が厚くなってくればなおさらだし、カーネルで動作させたい程度には重要なプログラムではあるはずなので、あまりtest suiteが提供されていないのにはもやっとしています。

Ciliumではユニットテスト環境をコンテナで作ってモックをはさみながらテストしているようです。

https://github.com/cilium/cilium/pull/16862
### 普通にセットアップが面倒くさい
pure RustをうたったeBPFライブラリ [Aya](https://github.com/aya-rs/aya) というのがあるので、そちらだとランタイム依存がすっきりしててセットアップ楽なのかな、と想像しています。
ちょうどタイムリーに記事が出た [RustでeBPFを操れるayaを触ってみた](https://qiita.com/moriai/items/c96636d35ae39809b45e) を拝見するとプロジェクトテンプレートを使って足場を作るようなのでいくらか手間は軽減されている可能性があります。

### 新しめのカーネルじゃないと厳しい
eBPFの機能はLinuxカーネルのバージョンアップとともに徐々に追加されているため、使っているディストリビューションの最新バージョンのカーネルじゃないと使いたい機能が入っていなかったりします。

[BPF Features by Linux Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) を見るだけではなく、各ディストリビューションのドキュメントも探してみる必要があります。読んでも自明じゃないものもあったりするので難しいです。

### tc-bpfのプログラムをアタッチするのはめんどくさい
libbpf-rsが生成するスケルトンからtc-bpfのアタッチを実行することはできず、
