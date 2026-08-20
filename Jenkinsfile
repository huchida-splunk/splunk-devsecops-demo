// Java(petclinic)デモ用パイプライン。各段の結果をSplunk HEC(/event)へ送る。
// prefix-swap検知の肝: mvn dependency:list を1依存=1イベントで送り、Splunk側watchlistで判定。
// CVE検知: ビルド後のSpring Boot fat jar(log4j-core 2.14.1同梱)をTrivyでスキャン。
pipeline {
  agent any
  environment {
    HECBASE = "${SPLUNK_HEC_URL}"
    TOKEN   = "${SPLUNK_HEC_TOKEN}"
    APP     = "spring-petclinic"
  }
  stages {
    stage('Checkout') { steps { checkout scm } }

    stage('依存リストをSplunkへ') {
      steps {
        sh '''
          set +e
          COL="${HECBASE%/raw}"; COL="${COL%/event}"
          mvn -q dependency:list -DoutputFile=deps.txt -DappendOutput=false
          : > events.jsonl
          grep -E "^[[:space:]]+[a-z]" deps.txt | sed "s/^[[:space:]]*//" | while read line; do
            coord=$(echo "$line" | awk "{print \\$1}")
            gid=$(echo "$coord" | cut -d: -f1); aid=$(echo "$coord" | cut -d: -f2); ver=$(echo "$coord" | cut -d: -f4)
            [ -z "$gid" ] && continue
            printf '{"index":"devsecops","sourcetype":"maven:deps","event":{"app":"%s","build":"%s","commit":"%s","actor":"ai-agent","groupId":"%s","artifactId":"%s","version":"%s"}}\\n' \
              "$APP" "$BUILD_NUMBER" "${GIT_COMMIT:-unknown}" "$gid" "$aid" "$ver" >> events.jsonl
          done
          echo "送信イベント数: $(wc -l < events.jsonl)"
          curl -sk "$COL" -H "Authorization: Splunk $TOKEN" --data-binary @events.jsonl -w "\\nmaven:deps HEC %{http_code}\\n"
          exit 0
        '''
      }
    }

    stage('Build (package)') { steps { sh 'rm -f trivy.json trivy-events.jsonl deps.txt events.jsonl; mvn -q -DskipTests package' } }

    stage('SCA (Trivy)') {
      steps {
        sh '''
          set +e
          COL="${HECBASE%/raw}"; COL="${COL%/event}"
          trivy fs --quiet --format json --scanners vuln --severity HIGH,CRITICAL --skip-dirs target . > trivy.json 2>/dev/null
          jq -c --arg app "$APP" --arg build "$BUILD_NUMBER" --arg commit "${GIT_COMMIT:-unknown}" \
            '.Results[]?.Vulnerabilities[]? | {index:"devsecops",sourcetype:"trivy:finding",event:{app:$app,build:$build,commit:$commit,pkg:.PkgName,installed:.InstalledVersion,cve:.VulnerabilityID,severity:.Severity,title:.Title}}' \
            trivy.json > trivy-events.jsonl
          echo "Trivy検知数: $(wc -l < trivy-events.jsonl)"
          if [ -s trivy-events.jsonl ]; then
            curl -sk "$COL" -H "Authorization: Splunk $TOKEN" --data-binary @trivy-events.jsonl -w "\\ntrivy HEC %{http_code}\\n"
          fi
          exit 0
        '''
      }
    }
  }
  post {
    always {
      script {
        def r = currentBuild.currentResult
        def d = currentBuild.duration ?: 0
        sh """
          COL="\${HECBASE%/raw}"; COL="\${COL%/event}"
          printf '{"index":"devsecops","sourcetype":"jenkins:build","event":{"app":"%s","build":"%s","commit":"%s","result":"%s","duration_ms":%s}}\\n' \
            "\$APP" "\$BUILD_NUMBER" "\${GIT_COMMIT:-unknown}" "${r}" "${d}" | \
            curl -sk "\$COL" -H "Authorization: Splunk \$TOKEN" --data-binary @- -w "\\njenkins:build HEC %{http_code}\\n"
          exit 0
        """
      }
    }
  }
}
