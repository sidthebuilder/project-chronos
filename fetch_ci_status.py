import json
import sys
import urllib.request

# Note: fetching job logs might require auth. If it fails, we will print the error.
url = 'https://api.github.com/repos/sidthebuilder/project-chronos/actions/runs?branch=feat/ai-brain'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
try:
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        for run in data.get('workflow_runs', [])[:5]:
            if run['name'] == 'CHRONOS CI' and run['status'] == 'completed':
                jobs_url = run['jobs_url']
                with urllib.request.urlopen(urllib.request.Request(jobs_url, headers={'User-Agent': 'Mozilla/5.0'})) as j_resp:
                    j_data = json.loads(j_resp.read().decode())
                    for job in j_data['jobs']:
                        if job['conclusion'] == 'failure':
                            print(f"\n--- FAILED JOB: {job['name']} ---")
                            log_url = f"https://api.github.com/repos/sidthebuilder/project-chronos/actions/jobs/{job['id']}/logs"
                            try:
                                log_req = urllib.request.Request(log_url, headers={'User-Agent': 'Mozilla/5.0'})
                                with urllib.request.urlopen(log_req) as log_resp:
                                    logs = log_resp.read().decode()
                                    lines = logs.split('\n')
                                    print("\n".join(lines[-100:]))
                            except Exception as log_e:
                                print(f"Could not fetch logs for job {job['id']}: {log_e}")
                break
except Exception as e:
    print('Failed:', e)
