# ⚠️ Splunk DevSecOps デモ用リポジトリ

これはSplunkのDevSecOpsデモ専用の `spring-petclinic` フォークです。本番利用しないでください。

デモの目的で、以下を意図的に含んでいます。

- `org.fasterxml.jackson.core:jackson-databind`(正規は `com.fasterxml.jackson.core`)という prefix-swap を模した依存座標。実体は `local-repo/` 配下の無害なマーカーjar(ペイロードなし)で、外部レジストリには公開していません。
- `org.apache.logging.log4j:log4j-core:2.14.1`(Log4Shell / CVE-2021-44228 を含む既知の脆弱バージョン)。

Jenkins パイプライン(`Jenkinsfile`)が各段の結果を Splunk に送信し、Splunk 側で「スキャナ単体では見えない偽装座標」と「既知脆弱性」を横断検知する様子をデモします。

<!-- poll-trigger test 182808 -->
