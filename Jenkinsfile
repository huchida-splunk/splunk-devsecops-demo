// Java(petclinic)デモ用パイプライン。各段の結果をSplunk HEC(/event)へ送る。
// prefix-swap検知の肝: mvn dependency:list を1依存=1イベントでSplunkに送り、Splunk側watchlistで判定。
pipeline {
  agent any
  environment {
    HECBASE = "${SPLUNK_HEC_URL}"   // 例 https://splunk:8088/services/collector
    TOKEN   = "${SPLUNK_HEC_TOKEN}"
    APP     = "spring-petclinic"
  }
  stages {
    stage('Checkout') { steps { checkout scm } }

    stage('依存リストをSplunkへ') {
      steps {
        sh '''
          set +e
          mvn -q dependency:list -DoutputFile=deps.txt -DappendOutput=false
          COL="${HECBASE%/raw}"; COL="${COL%/event}"   # /services/collector に正規化
          : > events.jsonl
          grep -E "^[[:space:]]+[a-z]" deps.txt | sed "s/^[[:space:]]*//" | while read line; do
            coord=$(echo "$line" | awk "{print \\$1}")
            gid=$(echo "$coord" | cut -d: -f1); aid=$(echo "$coord" | cut -d: -f2); ver=$(echo "$coord" | cut -d: -f4)
            [ -z "$gid" ] && continue
            printf '{"index":"devsecops","sourcetype":"maven:deps","event":{"app":"%s","build":"%s","commit":"%s","actor":"ai-agent","groupId":"%s","artifactId":"%s","version":"%s"}}\\n' \
              "$APP" "$BUILD_NUMBER" "${GIT_COMMIT:-unknown}" "$gid" "$aid" "$ver" >> events.jsonl
          done
          echo "送信イベント数: $(wc -l < events.jsonl)"
          curl -sk "$COL" -H "Authorization: Splunk $TOKEN" --data-binary @events.jsonl -w "maven:deps HEC %{http_code}\\n"
        '''
      }
    }

    stage('SCA (Trivy fs)') {
      steps {
        sh '''
          set +e
          COL="${HECBASE%/raw}"; COL="${COL%/event}"
          trivy fs --quiet --format json --scanners vuln --severity HIGH,CRITICAL . > trivy-fs.json 2>/dev/null
          jq -c --arg app "$APP" --arg build "$BUILD_NUMBER" --arg commit "${GIT_COMMIT:-unknown}" \
            '.Results[]?.Vulnerabilities[]? | {index:"devsecops",sourcetype:"trivy:finding",event:{app:$app,build:$build,commit:$commit,pkg:.PkgName,installed:.InstalledVersion,cve:.VulnerabilityID,severity:.Severity,title:.Title}}' \
            trivy-fs.json > trivy-events.jsonl
          echo "Trivy検知数: $(wc -l < trivy-events.jsonl)"
          [ -s trivy-events.jsonl ] && curl -sk "$COL" -H "Authorization: Splunk $TOKEN" --data-binary @trivy-events.jsonl -w "trivy HEC %{http_code}\\n"
        '''
      }
    }

    stage('Build (package)') { steps { sh 'mvn -q -DskipTests package || true' } }
  }
  post {
    always {
      sh '''
        COL="${HECBASE%/raw}"; COL="${COL%/event}"
        printf '{"index":"devsecops","sourcetype":"jenkins:build","event":{"app":"%s","build":"%s","commit":"%s","actor":"ai-agent","result":"done"}}\\n' \
          "$APP" "$BUILD_NUMBER" "${GIT_COMMIT:-unknown}" | \
          curl -sk "$COL" -H "Authorization: Splunk $TOKEN" --data-binary @- -w "jenkins:build HEC %{http_code}\\n" || true
      '''
    }
  }
}
