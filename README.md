﻿# IPA-DN-Ultra ライブラリ リリースノート (更新履歴)

この更新履歴ファイルの最新版は、[https://github.com/IPA-CyberLab/IPA-DN-Ultra/](https://github.com/IPA-CyberLab/IPA-DN-Ultra/) を参照してください。


このライブラリは未完成です。まだ使用することはできません。2021/1/20 登

## [Current Version] beta7preview9

## beta7preview9
1. シン・テレワークシステム サーバーの自動インストーラ (無人インストーラ) に対応した。大量のコンピュータへのサーバーのインストールが快適になる。インストーラの EXE ファイルを実行する際に「/auto:1」というコマンドラインオプションを指定することにより、インストーラはデフォルトのオプションのまま、無人で最後まで進み、サーバー設定ツールが自動的に起動するところまで進むようになる。なお、このコマンドラインオプションを指定して実行する際には、Administrators 権限が必要である。権限がない場合は、UAC ポップアップが表示される。また、インストール中にデフォルトで次に進むことができないようなエラーが発生した場合は、当該エラーの表示部分で停止するので、それ以降は手動でインストールをする必要がある。
1. プライベート版で完全閉域化ファイアウォール機能に対応した。アプリケーションビルド時において、ソースコード中の「src/Vars/VarsActivePatch.h」の「ThinFwMode」項目を「true」に変更することにより、「完全閉域化ファイアウォール」機能がクライアント接続時に呼び出されるようになる。「完全閉域化ファイアウォール」において通信を例外的に許可する通信先 IP アドレス (IP サブネット) のリストは、インストーラのビルド時に予め「src/bin/hamcore/WhiteListRules.txt」に列挙しておく必要がある。クライアント側も新しいバージョンが必要である。
1. アプリのインストーラビルド時のソースコード中の「src/Vars/VarsActivePatch.h」の「ThinFwMode」項目が「false」の場合であっても、ポリシー規制サーバーで「ENFORCE_LIMITED_FIREWALL」項目を「1」に設定することにより、「完全閉域化ファイアウォール」機能を強制的に有効にすることができるようにした。クライアント側も新しいバージョンが必要である。プライベート版と LGWAN 版では利用できるが、パブリック版では利用できない。
1. サーバー側で「tunnel_log」ディレクトリにサーバーと中継システムとの間の通信の詳細なログを出力するようにした。サーバーと中継システムとの間が頻繁に切れるような場合は、このログを確認することにより、原因を特定することが容易となる。
1. インストーラのビルドにおいて、サーバーアプリのみをビルドすることができるようになった。ソースコード中の「src/Vars/VarsActivePatch.h」の「ThinSetupServerOnly」項目を「true」に変更することにより、サーバーアプリのみを含むインストーラが作成される。クライアントアプリも含むインストーラと、サーバーアプリのみを含むインストーラの 2 種類をビルドしたい場合は、同ヘッダファイルを書換えて、2 回ビルドすること。
1. 「MAC アドレス認証における MAC アドレスのリストを、ポリシー規制サーバー側で一元管理し、ユーザーに自由に管理させたくない」という要望に対応するため、ポリシー規制サーバーの設定ファイルに「NO_LOCAL_MAC_ADDRESS_LIST」を追加した。これを「1」に設定することにより、ユーザーは MAC アドレス認証における MAC アドレスのリストを手動で設定することができなくなる。なお、「NO_LOCAL_MAC_ADDRESS_LIST」が有効となるためには、ポリシー設定ファイルの「CLIENT_ALLOWED_MAC_LIST_URL」および「ENFORCE_MACCHECK」が設定されている必要がある。
1. LGWAN 版において、クライアントが Administrators または SYSTEM 権限で動作している場合は、ユーザーが指定した mstsc.exe ファイルを実行することができないようにした。
1. OTP における SMS 認証に対応した。(ハイパースケール版のみ。) 詳細は、ハイパースケール版のドキュメントの 8-19 節「OTP を電子メールの代わりに SMS で送信する方法」を参照すること。
1. インストーラの EXE ファイルと同じディレクトリに EntryPoint.dat ファイル (テキストファイル) が設置されている場合は、このファイルが、インストーラビルド時に埋め込まれる EntryPoint.dat ファイルに優先して、サーバーと共にインストールされるようにした。これは、たとえばシン・テレワークシステム中継システムを組み込んだアプライアンスを実装したとき、HTML 管理画面等から、その中継システムに接続できるインストーラの ZIP ファイルをダウンロードできるような機能を実装する際に、大変便利である。EXE ファイルそのものはすべてのシステムで共通にしておき、EntryPoint.dat ファイルのみ、システム毎に異なるファイルを自動生成して ZIP でダウンロード可能とするシステムを、容易に構築できるようになった。このことにより、ユーザーはインストーラを独自にビルドする必要がなく、当該アプライアンスの製造元が 1 回のみビルドすればよい。そして、このことは Microsoft Authenticode 署名をインストーラにアプライアンス出荷元があらかじめ付与することができることも意味するのである。
1. クライアント証明書認証における OCSP (Online Certificate Status Protocol) 検証の実装。ポリシー規制サーバーの「ENABLE_OCSP」項目を「1」に設定することにより、サーバーは、クライアント証明書認証要求があった場合で、かつ認証がサーバーにあらかじめ登録されている信頼された証明書 (CA 等) による署名の検証によって実施される場合に、当該クライアント証明書の拡張フィールドに OCSP サーバーの URL が記載されている場合は、その OCSP サーバーの URL 宛に OCSP プロトコルにより証明書が有効かどうかの検証を試みます。無効であると回答された場合は、ログファイルにその旨を記載し、証明書認証は失敗します。OCSP サーバーとの通信に失敗した場合は、検証は成功したものとみなされます。
1. アカウントロックアウト機能の実装。ポリシー規制サーバーの「AUTH_LOCKOUT_COUNT」および「AUTH_LOCKOUT_TIMEOUT」項目を 1 以上の整数に設定することにより、ユーザー認証 (パスワード認証) においてパスワードを誤った場合のアカウントロックアウトが可能となりました。AUTH_LOCKOUT_COUNT には、ロックアウトが発生するまでの認証失敗回数を指定します。AUTH_LOCKOUT_TIMEOUT には、ロックアウトが自動解除されるまでのタイムアウト値を秒単位で指定します。
1. 無操作時のタイムアウト実装。ポリシー規制サーバーの「IDLE_TIMEOUT」項目を 1 以上の整数に設定することにより、ユーザーがクライアント側でマウスを「IDLE_TIMEOUT」で指定された秒数以上無操作であった場合は、クライアント側の接続が切断され、無操作タイムアウトが発生した旨のメッセージボックスがクライアント側の画面に表示されるようになります。この機能が有効となるには、クライアント側のバージョンも beta7preview9 以降である必要があります。それ以前のクライアントの場合は、無視されます。
1. ポリシー規制サーバーの「SERVER_ALLOWED_MAC_LIST_URL」による MAC アドレス一覧テキストファイルの指定において、MAC アドレス一覧テキストファイルの先頭行に UTF-8 の BOM 文字が入っていた場合、その BOM 文字を除外して処理を行なうように改良しました。
1. 空きメモリ容量が十分でない場合、「サーバー設定ツール」で警告メッセージが表示されるようにしました。


## beta7preview8
1. プライベート版 (ハイパースケール版) を実装しました。
1. コントローラの完全冗長に対応しました。
1. サーバー版で詳細デバッグログを保存する機能を実装しました。
1. (LGWAN 版のみ) インストール時に RDP がポリシーで無効になっている場合は、クリップボードおよびファイル共有をインストール時に無効化し、その代わり、毎回の接続時にはポリシーをいじらないようにした。また、インストール時に RDP がポリシーで無効になっている場合は、その旨のメッセージを表示するようにした。
1. サーバー側ソフトウェアにおいて、Windows のローカルグループポリシーまたはドメイングループポリシーでリモートデスクトップが無効である場合でも接続受付時に強制的に有効にするようにしました。


## beta7preview6
1. クライアント接続中はクライアント側 PC のシステムがスリープしないようにしました。
1. 統計機能を実装しました。


## beta7preview1-5
1. プライベート版 (スタンドアロン版) を実装しました。
1. Windows において Admin 権限を有しているかどうかの判定を厳密化しました。
1. (LGWAN 版のみ) クリップボード履歴の保存を禁止しました。Windows 標準のスクリーンショットホットキーによるスクリーンショット撮影を禁止しました。
1. サーバーでリモートアクセス中におけるプロセスの起動 / 終了のログを保存できるようにしました。
1. ゲートウェイで DisableDoSProtection オプションを実装しました。
1. LGWAN 版を実装しました。
1. ポリシーで OTP、MAC アドレス検査、クライアント検疫検査、透かし を強制的に無効化できるようにしました。
1. MAC アドレスリストがマルチスレッド競合によって稀に消えてしまう問題を解決しました。
1. 完全閉域 FW をオプションで OFF にもできるようにしました。
1. 登録キーに対応しました。
1. Proxy Protocol に対応しました。
1. Windows 10 2004 クリーンインストール環境で「Windows Hello 認証」が強制されている場合は、RDP 接続ができない問題があるため、強制を解除するようにしました。
1. ソースコードをサブモジュールに分離し、アクティブパッチやブランディングを可能にしました。
1. Visual Studio 2019 によるビルドに対応しました。
1. WhiteList Rules でプライベート IP の範囲が間違っていたのを修正しました。
1. 行政モードでサーバー側が検疫 ON の場合は、必ず FW 機能を強制するようにしました。


# beta6
1. Wake on LAN 機能 (接続先端末の電源を自宅から ON する機能)
1. 画面撮影・キャプチャ防止のための電子透かし機能
1. 固有 ID 初期化機能 (VDI クローン対応)
1. クライアント MAC アドレス認証のポリシーサーバーによるリスト一元管理機能
1. 完全閉域化 FW 機能 (リモート利用中はユーザー自宅 PC とインターネットとの間を完全に遮断)
1. ポリシーサーバーによるサーバー端末の明示的着信許可機能 (リストに登録されていないサーバー端末は動作禁止する)


# beta5
1. 二要素認証・ワンタイムパスワード (OTP) 機能
1. マイナンバーカードを用いたユーザー認証機能
1. クライアント検疫機能・MAC アドレス認証機能
1. エンタープライズ環境用ポリシー規制サーバー機能
1. 行政情報システム適応モード (中継システムの IP 範囲の限定)


# beta4
1. 「ワンタイムパスワード認証 (OTP)」 を追加しました。企業環境での既存のセキュリティポリシーに準拠するため、「二要素認証に対応してほしい」、「OTP に対応してほしい」というご要望にお応えして、新規開発をいたしました。


# beta3
1. 「仮想マルチディスプレイ機能」を追加しました。「職場の PC」にディスプレイが 1 枚しかない場合でも、自宅の PC にディスプレイが 2 枚以上あれば、自宅から職場の PC をリモート操作する際にマルチディスプレイ化して、大変快適に操作することができます。
1. 「パスワード複雑性を満たしていなくても、警告を無視すれば簡単なパスワードを設定できるのは良くないのではないか。」というご意見をいただきましたので、パスワード複雑性を満たしていないパスワードを設定することをできなくしました。(Beta 2 までは警告メッセージは無視可能でしたが、Beta 3 では、無視可能な警告メッセージは廃止され、無視することができないエラーメッセージとなりました。)
1. パスワード複雑性の規則を見直し、(1) 8 文字以上で、小文字・大文字・数字・記号のうち少なくとも 3 種類以上が使用されている。(2) 16 文字以上で、小文字・大文字・数字・記号のうち少なくとも 2 種類以上が使用されている。(3) 24 文字以上である。のいずれかを満たしていれば可としました。
1. 「シン・テレワークシステム サーバー」および「シン・テレワークシステム クライアント」と、中継システムとの間の通信のセキュリティ (可用性) を向上しました。中継システムにおけるロードバランサとの間の通信が、何らかの通信障害により確立できない場合は、セカンダリロードバランサに対して接続を試みるようになりました。また、セカンダリロードバランサを、複数のドメインおよび AS に分散して配置しました。これにより、通信経路に障害があり 1 つのロードバランサと通信ができない場合でも、他のロードバランサに迂回して通信が確立できるようになりました。
1. 「シン・テレワークシステム クライアント」の起動時に、より新しいバージョンが利用可能になっている場合は画面に案内を表示するようにしました。この機能は、「バージョン情報」画面から無効にできます。

# beta2
1. 「高度なユーザー認証」機能の証明書認証で、X.509 証明書のビット数が 1024 bit より大きい場合に認証に失敗する問題を解決しました。
1. HTTP プロキシサーバーを経由する場合の User Agent の文字列をユーザーが自由に変更できるようにしました。
1. グループポリシーで RDP が無効となっている場合でも、RDP を用いたシステムモードでの接続ができるようにしました。
1. ユーザーのコンピュータのハードディスクが予め攻撃者により別の手段により侵害され、マルウェアのファイルが保存されている場合で、ユーザーが、当該マルウェアと同じディレクトリに本プログラムのインストーラを置いて実行すると、マルウェアも実行されてしまう場合があるセキュリティ問題を解決しました。これはいわゆる DLL プリロード問題と呼ばれる Windows の設計上の脆弱性がもとで発生する問題です。アプリケーション側での対策を施しました。日下部司氏からの報告によるものです。ありがとうございました。
1. クライアントに「リラックス・モード」を追加しました。テレワークの開始前に、リラックスすることができます。デフォルトで無効になっていますが、クライアントのオプション設定から有効にできます。ぜひ、有効にしてみてください。

# beta1
最初のバージョンです。
