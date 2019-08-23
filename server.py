#!/usr/bin/python3
# -*- coding: utf-8 -*-

import time
import json as jsn
import socket
import threading
import http.server
import requests
import os
import sys
import base64
import datetime
import argparse


def check_repo_in_config(repo):
    for element in config['repositories']:
        if element['source'] == repo:
            return 'source'
        if element['target'] == repo:
            return 'target'
    else:
        return False


def get_repo_pair_in_config(repo_param):
    for repo in config['repositories']:
        if repo['source'] == repo_param:
            return repo['target']
        if repo['target'] == repo_param:
            return repo['source']

    return False


def sync(sync_list, repo, gh=None, cmd=None):
    src_repo = repo
    trg_repo = get_repo_pair_in_config(src_repo)
    status = True
    message = dict()
    message['message'] = ''
    message['code'] = 200
    message['cmd'] = cmd
    message['repo'] = repo
    if gh:
        message['gh'] = gh
    for src_file in sync_list:
        status = False
        data = dict()
        data['committer'] = dict()
        data['committer']['name'] = user
        data['committer']['email'] = email
        data['message'] = 'autosync ' + datetime.datetime.now().isoformat()
        trg_file = get_file_pair_in_config(src_file, src_repo)
        response = transform(src_file, src_repo)
        if response:
            resp = logic_fix(jsn.loads(response.decode('utf-8')))
            data['content'] = base64.b64encode(bytes(jsn.dumps(resp, indent=2), 'utf-8')).decode()

            for branch in config['branches']:
                data['branch'] = 'refs/heads/' + branch
                sha = get_sha(trg_file, trg_repo, branch)
                if sha:
                    data['sha'] = sha

                url_trg = 'https://api.github.com/repos/' + trg_repo + '/contents/' + trg_file + \
                          '?access_token=' + token_github
                data_json = jsn.dumps(data)
                response = requests.put(url_trg, data=data_json, headers={'Content-Type': 'application/json'}).json()

                # check
                if 'commit' in response:
                    message['message'] = 'Commit to ' + branch + ' succeeded'
                    message['code'] = 200
                    status = True
                else:
                    message['message'] = 'Commit to ' + branch + ' failed'
                    message['code'] = 500
                    print(jsn.dumps(message, indent=2))
        else:
            return {'message': 'APIMatic transformation failed'}, 500

    if not status:
        return {'message': 'Transformation failed'}, 500
    else:
        return {'message': 'Transformation succeeded'}, 200


def parse_request_line(request_line):
    request_line = request_line.split('HTTP')[0].strip()
    method = request_line.split('/')[0].strip()
    cmd = request_line.split('/')[1].strip().split('?')[0]
    param = dict()
    if cmd in ['sync', 'config']:
        if len(request_line.split('?')) > 1:
            for element in request_line.split('?')[1].split('&'):
                if element.split('=')[0] in ['repo', 'token']:
                    param[element.split('=')[0]] = element.split('=')[1]

    if method == 'GET' and cmd in cmd_get_rl:
        return cmd, param
    if method == 'POST' and cmd in cmd_post_rl:
        return cmd, param

    return False, None


def get_file_pair_in_config(file_param, repo_param):
    check = check_repo_in_config(repo_param)
    for repo in config['repositories']:
        if repo[check] == repo_param:
            for file in repo['files']:
                if file['source'] == file_param:
                    return file['target']
    return False


def get_sha(file, repo, branch):
    url = 'https://api.github.com/repos/' + repo + '/contents/' + file + '?ref=' + branch
    response = requests.get(url).json()
    if 'sha' in response:
        return response['sha']
    else:
        return False


def logic_fix(file):
    for path in file['paths']:
        for element in file['paths'][path]:
            file['paths'][path][element]['operationId'] = file['paths'][path][element]['summary']
    return file


def transform(file, repo):
    api = config['format']

    description = 'https://raw.githubusercontent.com/' + repo + '/master/' + file
    url = 'https://apimatic.io/api/transform?format=' + api + '&descriptionUrl=' + description

    event.acquire()
    while True:
        response = requests.get(url, headers={'Authorization': 'X-Auth-Key ' + token_apimatic})
        if response.status_code == 200:
            break
        if response.status_code == 400:
            break
        if response.status_code == 401:
            break
    event.release()

    if response.status_code != 200:
        return False
    else:
        return response.content


def prepare_list(request, repo, cmd):
    if cmd == 'push':
        commits = request['commits']
        commits.append(request['head_commit'])
        raw_list = list()
        for i in commits:
            if 'created' in i:
                for j in i['created']:
                    raw_list.append(j)
            if 'modified' in i:
                for j in i['modified']:
                    raw_list.append(j)
        files_in_commits = list(set(raw_list))

    raw_list = list()
    for i in config['repositories']:
        if i['source'] == repo:
            for j in i['files']:
                if cmd == 'push':
                    if j['source'] in files_in_commits:
                        raw_list.append(j['source'])
                if cmd == 'sync':
                    raw_list.append(j['source'])

    to_sync = list(set(raw_list))

    if len(to_sync) > 0:
        return to_sync
    else:
        return False


class Handler(http.server.BaseHTTPRequestHandler):

    def reply(self, message=dict(), silent=False, code=200, gh='', cmd='', repo=''):
        self.send_response(code)
        self.send_header('content-type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(jsn.dumps(message, indent=2) + '\n', 'utf8'))

        if not silent:
            message['code'] = code
            if self.headers.get('X-Real-IP'):
                message['ip'] = self.headers.get('X-Real-IP')
            else:
                message['ip'] = self.client_address[0]
            message['request'] = self.requestline
            message['date'] = datetime.datetime.now().isoformat()
            if cmd:
                message['cmd'] = cmd
            if repo:
                message['repo'] = repo
            if self.headers.get('X-GitHub-Delivery'):
                message['gh'] = self.headers.get('X-GitHub-Delivery')
            print(jsn.dumps(message, indent=2))
        return

    def log_message(self, format, *args):
        return

    def do_POST(self):
        cmd, param = parse_request_line(self.requestline)
        if not cmd:
            cmd = self.headers.get('X-GitHub-Event')

        if not cmd:
            message = {'message': 'Request not found'}
            self.reply(message, code=404)
            return

        if cmd not in cmd_post:
            message = {'message': 'Request not found'}
            self.reply(message, code=404, cmd=cmd)
            return

        if cmd in cmd_post_hr_ignored:
            message = {'message': 'Request ignored'}
            self.reply(message, cmd=cmd)
            return

        if cmd == 'ping':
            message = {'message': 'Pong'}
            self.reply(message, cmd=cmd)
            return

        if cmd not in cmd_post_rl:
            content_length = int(self.headers.get('content-length'))

            if content_length == 0:
                message = {'message': 'Length Required'}
                self.reply(message, code=411, cmd=cmd)
                return

            body = self.rfile.read(content_length).decode('utf-8')

            try:
                body = jsn.loads(body)
            except ValueError:
                message = {'message': 'Unsupported media type'}
                self.reply(message, code=400, cmd=cmd)
                return

        status = True
        if cmd in cmd_post_rl:
            if 'repo' in param:
                repo = param['repo']
            else:
                status = False
        elif 'repository' in body:
            if 'full_name' in body['repository']:
                repo = body['repository']['full_name']
            else:
                status = False
        else:
            status = False

        if not status:
            message = {'message': 'Bad request, repository not defined'}
            self.reply(message, code=400, cmd=cmd)
            return

        check = check_repo_in_config(repo)

        if not check:
            message = {'message': 'Repository not found'}
            self.reply(message, code=404, cmd=cmd, repo=repo)
            return

        if check == 'target':
            message = {'message': 'Target repo, ignored'}
            self.reply(message, cmd=cmd, repo=repo)
            return

        if cmd == 'sync':
            sync_list = prepare_list(None, repo, cmd)
            message, code = sync(sync_list, repo)
            self.reply(message, code=code, cmd=cmd, repo=repo)
            return

        if cmd == 'push':
            if body['ref'].split('/')[:3][2] != 'master':
                message = {'message': 'Branch not master, ignored'}
                self.reply(message, cmd=cmd, repo=repo)
                return

            sync_list = prepare_list(body, repo, cmd)
            if not sync_list:
                message = {'message': 'Files in commit not match config'}
                self.reply(message, cmd=cmd, repo=repo)
                return
            else:
                message, code = sync(sync_list, repo)
                self.reply(message, code=code, cmd=cmd, repo=repo)
                return

        message = {'message': 'Hook not found'}
        self.reply(message, code=404, cmd=cmd, repo=repo)
        return

    def do_GET(self):
        cmd, param = parse_request_line(self.requestline)
        if not cmd:
            message = {'message': 'Request not found'}
            self.reply(message, code=404)
            return

        if cmd == 'ping':
            message = {'message': 'Pong'}
            self.reply(message, silent=True, cmd=cmd)
            return

        if cmd == 'version':
            message = {'message': version}
            self.reply(message, cmd=cmd)
            return

        if cmd == 'config':
            status = False
            if 'token' in param:
                if param['token'] == token:
                    message = {'message': config}
                    self.reply(message, cmd=cmd)
                else:
                    status = True
            else:
                status = True

            if status:
                message = {'message': 'Access denied'}
                self.reply(message, code=401, cmd=cmd)
            return

        if cmd == 'apimatic':
            if transform('api-source.md', 'Fiware-test/service.apispectransformer-source'):
                message = {'message': 'Test succeeded'}
                self.reply(message, cmd=cmd)
            else:
                message = {'message': 'Test failed'}
                self.reply(message, code=500, cmd=cmd)
            return


class Thread(threading.Thread):
    def __init__(self, i):
        threading.Thread.__init__(self)
        self.i = i
        self.daemon = True
        self.start()

    def run(self):
        httpd = http.server.HTTPServer(address, Handler, False)

        httpd.socket = sock
        httpd.server_bind = self.server_close = lambda self: None

        httpd.serve_forever()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', dest="ip", default='0.0.0.0', help='ip address (default: 0.0.0.0)', action="store")
    parser.add_argument('--port', dest="port", default=8000, help='port (default: 8000)', action="store")
    parser.add_argument('--config', dest='config_path', default='/opt/config.json',
                        help='path to config file (default: /opt/config.json)',  action="store")
    parser.add_argument('--user', dest='user', default='Fiware-ops', help='github user (default: Fiware-ops)',
                        action="store")
    parser.add_argument('--email', dest='email', default='test@example.com',
                        help='github user (default: test@example.com)', action="store")
    parser.add_argument('--threads', dest='threads', default=0, help='threads to start (default: len(repos)//2 + 3)',
                        action="store")
    parser.add_argument('--socks', dest='socks', default=0, help='threads to start (default: threads)',  action="store")

    args = parser.parse_args()

    ip = args.ip
    port = args.port
    user = args.user
    email = args.email
    threads = args.threads
    socks = args.socks
    config_path = args.config_path

    if 'TOKEN_GITHUB' in os.environ:
        token_github = os.environ['TOKEN_GITHUB']
    else:
        print(jsn.dumps({'message': 'TOKEN_GITHUB not found', 'code': 500, 'cmd': 'start'}, indent=2))
        token_github = None
        sys.exit(1)

    if 'TOKEN_APIMATIC' in os.environ:
        token_apimatic = os.environ['TOKEN_APIMATIC']
    else:
        print(jsn.dumps({'message': 'TOKEN_APIMATIC not found', 'code': 500, 'cmd': 'start'}, indent=2))
        token_apimatic = None
        sys.exit(1)

    if 'TOKEN' in os.environ:
        token = os.environ['TOKEN']
    else:
        print(jsn.dumps({'message': 'TOKEN not found', 'code': 404, 'cmd': 'start'}, indent=2))
        token = None

    if not os.path.isfile(config_path):
        print(jsn.dumps({'message': 'Config file not found', 'code': 500, 'cmd': 'start'}, indent=2))
        config_file = None
        sys.exit(1)

    try:
        with open(config_path) as f:
            config = jsn.load(f)
    except ValueError:
        print(jsn.dumps({'message': 'Unsupported config type', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    print(jsn.dumps({'message': 'Checking config', 'code': 200, 'cmd': 'start'}, indent=2))

    if 'repositories' not in config:
        print(jsn.dumps({'message': 'Repositories not defined', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)
    elif len(config['repositories']) == 0:
        print(jsn.dumps({'message': 'Repositories list is empty', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)
    if 'format' not in config:
        print(jsn.dumps({'message': 'Format not defined', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)
    if 'branches' not in config:
        print(jsn.dumps({'message': 'Branches not defined', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)
    elif len(config['branches']) == 0:
        print(jsn.dumps({'message': 'Branches list is empty', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    st = True
    for el in config['repositories']:
        if 'source' in el and 'target' and 'files' in el:
            for el2 in el['files']:
                if 'source' and 'target' not in el2:
                    st = False
                    break
        else:
            st = False
            break

    if not st:
        print(jsn.dumps({'message': 'Error found in config', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    if threads == 0:
        threads = len(config['repositories'])//2 + 3
    if socks == 0:
        socks = threads

    address = (ip, port)

    cmd_get_rl = ['ping', 'config', 'version', 'apimatic']
    cmd_post_rl = ['sync']
    cmd_post_hr = ['ping', 'push']
    cmd_post_hr_ignored = ['check_run', 'check_suite', 'commit_comment', 'deployment', 'deployment_status', 'status',
                           'gollum', 'installation', 'installation_repositories', 'issue_comment', 'issues', 'label',
                           'marketplace_purchase', 'member', 'membership', 'milestone', 'organization', 'org_block',
                           'page_build', 'project_card', 'project_column', 'project', 'public', 'pull_request', 'fork',
                           'pull_request_review_comment', 'pull_request_review', 'repository', 'watch', 'team_add',
                           'repository_vulnerability_alert', 'team', 'create', 'delete', 'release']
    cmd_post = cmd_post_rl + cmd_post_hr + cmd_post_hr_ignored

    version_file = open(os.path.split(os.path.abspath(__file__))[0] + '/version').read().split('\n')
    version = dict()
    version['build'] = version_file[0]
    version['commit'] = version_file[1]

    event = threading.BoundedSemaphore(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(socks)

    [Thread(i) for i in range(threads)]

    print(jsn.dumps({'message': 'Service started', 'code': 200, 'threads': threads, 'socks': socks}, indent=2))

    while True:
        time.sleep(9999)
