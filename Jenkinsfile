// Java(petclinic)デモ用パイプライン。各段の結果をSplunk HECへ送る。
// prefix-swap検知の肝は mvn dependency:list を丸ごとSplunkに送り、Splunk側watchlistで判定する点。
pipeline {
  agent any
  environment {
    HEC   = "${SPLUNK_HEC_URL}"
    TOKEN = "${SPLUNK_HEC_TOKEN}"
    APP   = "spring-petclinic"
  }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('依存リストをSplunkへ') {
      steps {
        sh '''
          mvn -q dependency:list -DoutputFile=deps.txt -DappendOutput=false || true
          # 1依存=1イベント。groupId:artifactId:version を JSON 化してHEC(raw)へ
          grep -E '^\\s+[a-z]' deps.txt | sed 's/^[[:space:]]*//' | while read line; do
            coord=$(echo "$line" | awk '{print $1}')
            gid=$(echo "$coord" | cut -d: -f1); aid=$(echo "$coord" | cut -d: -f2); ver=$(echo "$coord" | cut -d: -f4)
            printf '{"app":"%s","build":"%s","commit":"%s","groupId":"%s","artifactId":"%s","version":"%s"}\\n' \
              "$APP" "$BUILD_NUMBER" "${GIT_COMMIT:-unknown}" "$gid" "$aid" "$ver"
          done | curl -s -k "$HEC/raw?sourcetype=maven:deps&index=devsecops" -H "Authorization: Splunk $TOKEN" --data-binary @-
        '''
      }
    }
    stage('SCA (OWASP Dependency-Check)') {
      steps {
        sh '''
          dependency-check --scan . --format JSON --out dc-report.json --project "$APP" || true
          jq -c --arg app "$APP" --arg build "$BUILD_NUMBER" --arg commit "${GIT_COMMIT:-unknown}" \
            '.dependencies[]? | select(.vulnerabilities) | .vulnerabilities[] as $v | {app:$app,build:$build,commit:$commit,fileName:.fileName,cve:$v.name,severity:$v.severity,cvss:($v.cvssv3.baseScore // null)}' \
            dc-report.json | curl -s -k "$HEC/raw?sourcetype=depcheck:finding&index=devsecops" -H "Authorization: Splunk $TOKEN" --data-binary @- || true
        '''
      }
    }
    stage('Build') {
      steps { sh 'mvn -q -DskipTests package || true' }
    }
    stage('Image Build + Trivy') {
      steps {
        sh '''
          docker build -t $APP:$BUILD_NUMBER . || true
          trivy image --quiet --format json --severity HIGH,CRITICAL $APP:$BUILD_NUMBER > trivy.json || true
          jq -c --arg app "$APP" --arg build "$BUILD_NUMBER" --arg commit "${GIT_COMMIT:-unknown}" \
            '.Results[]?.Vulnerabilities[]? | {app:$app,build:$build,commit:$commit,pkg:.PkgName,installed:.InstalledVersion,cve:.VulnerabilityID,severity:.Severity}' \
            trivy.json | curl -s -k "$HEC/raw?sourcetype=trivy:finding&index=devsecops" -H "Authorization: Splunk $TOKEN" --data-binary @- || true
        '''
      }
    }
  }
  post {
    always {
      sh '''
        printf '{"app":"%s","build":"%s","commit":"%s","result":"%s","actor":"%s"}\\n' \
          "$APP" "$BUILD_NUMBER" "${GIT_COMMIT:-unknown}" "${currentBuild_result:-DONE}" "ai-agent" | \
          curl -s -k "$HEC/raw?sourcetype=jenkins:build&index=devsecops" -H "Authorization: Splunk $TOKEN" --data-binary @- || true
      '''
    }
  }
}
