// Stage to paste into a service Jenkinsfile, right after the SBOM is generated (SBOMFIX-804).
// Exit codes: 0 unchanged, 1 corrected, 2 cannot fix, 3 forbidden data loss, 4 quality gate,
// 7 no component has a purl type Checkmarx supports (Checkmarx would fail the scan).
// The upload below uses the cx CLI, so the profile is checkmarx-cli (same versions as checkmarx: 1.6 and 1.7 are kept).
// Outputs: sbom.corrected.cdx.json (uploaded), sbom.tech-notes.md (what changed), sbom.suggestions.md (fix at the source).
stage('SBOM: correct for Checkmarx') {
  steps {
    sh '''
      set +e
      docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 \
        fix build/sbom.json --profile checkmarx-cli --out build/sbom-fixed
      rc=$?
      set -e
      if [ "$rc" -ge 2 ]; then
        echo "sbom-fixer exit code $rc - see build/sbom-fixed/sbom.tech-notes.md"
        exit "$rc"
      fi
    '''
  }
  post {
    always { archiveArtifacts artifacts: 'build/sbom.json, build/sbom-fixed/**', allowEmptyArchive: true }
  }
}

stage('Checkmarx SCA') {
  steps {
    // Use the flags your cx version documents for SBOM import (cx scan create --help).
    withCredentials([string(credentialsId: 'cx-client-secret', variable: 'CX_CLIENT_SECRET')]) {
      sh 'cx scan create --project-name "${JOB_NAME}" --branch "${BRANCH_NAME}" -s build/sbom-fixed/sbom.corrected.cdx.json --scan-types sca --sbom-only'
    }
  }
}
