# triage-party

This folder contains the triage party config and deploy script for the oss-fuzz instance of [triage-party](https://github.com/google/triage-party).

To make changes to triage party, you'll need to:
1. Make changes to the [config](oss-fuzz.yaml)
1. Deploy a new revision to Cloud Run via [deploy.sh](deploy.sh):

```
GITHUB_TOKEN_PATH=[path to file containing github token] DB_PASS=[CloudSQL database password]  ./deploy.sh 
```

Visit https://triage-party-pahypmb2lq-uc.a.run.app to join the party!
