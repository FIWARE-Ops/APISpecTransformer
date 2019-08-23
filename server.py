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


def get_file(file_hash, repo_hash):
    repo = config[repo_hash]['source']
    file = config[repo_hash]['files'][file_hash]['source']
    url = 'https://raw.githubusercontent.com/' + repo + '/master/' + file

    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    else:
        return False


def get_hash(param):
    return hash(param) % ((sys.maxsize + 1) * 2)


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


def prepare_list(request, repo_hash):
    to_sync = list()
    if not request:
        for i in config[repo_hash]['files']:
            to_sync.append(config[repo_hash]['files'][i]['source'])
    else:
        commits = request['commits']
        commits.append(request['head_commit'])
        cfg_files = list()
        for i in config[repo_hash]['files']:
            cfg_files.append(config[repo_hash]['files'][i]['source'])
        for i in commits:
            if 'added' in i:
                for j in i['added']:
                    if j in cfg_files:
                        to_sync.append(get_hash(j))
            if 'modified' in i:
                for j in i['modified']:
                    if j in cfg_files:
                        to_sync.append(get_hash(j))
        to_sync = list(set(to_sync))

    if len(to_sync) > 0:
        return to_sync
    else:
        return False


def sync(sync_list, repo_hash):
    trg_repo = config[repo_hash]['target']

    for src_file in sync_list:
        data = dict()
        data['committer'] = dict()
        data['committer']['name'] = user
        data['committer']['email'] = email
        data['message'] = 'autosync'

        trg_file = config[repo_hash]['files'][src_file]['target']

        if config[repo_hash]['files'][src_file]['transform']:
            response = transform(src_file, repo_hash)
            response = logic_fix(jsn.loads(response.decode('utf-8')))
            response = jsn.dumps(response, indent=2)
        else:
            response = get_file(src_file, repo_hash)
            response = response.decode()
        if response:
            data['content'] = base64.b64encode(bytes(response, 'utf-8')).decode()

            for branch in dst_branches:
                data['branch'] = 'refs/heads/' + branch
                sha = get_sha(trg_file, trg_repo, branch)
                if sha:
                    data['sha'] = sha

                url_trg = 'https://api.github.com/repos/' + trg_repo + '/contents/' + trg_file + \
                          '?access_token=' + token_github
                data_json = jsn.dumps(data)
                response = requests.put(url_trg, data=data_json, headers={'Content-Type': 'application/json'}).json()

                if 'commit' not in response:
                    return {'message': 'GitHub commit failed'}, 500

        else:
            return {'message': 'APIMatic transformation failed'}, 500

    return {'message': 'Synchronization succeeded'}, 200


def transform(file_hash, repo_hash):
    if repo_hash != test_repo:
        repo = config[repo_hash]['source']
    else:
        repo = repo_hash
    if file_hash != test_file:
        file = config[repo_hash]['files'][file_hash]['source']
    else:
        file = file_hash

    description = 'https://raw.githubusercontent.com/' + repo + '/master/' + file
    url = 'https://apimatic.io/api/transform?format=' + dst_format + '&descriptionUrl=' + description

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


class Handler(http.server.BaseHTTPRequestHandler):

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
            if transform(test_file, test_repo):
                message = {'message': 'Test succeeded'}
                self.reply(message, cmd=cmd)
            else:
                message = {'message': 'Test failed'}
                self.reply(message, code=500, cmd=cmd)
            return

    def do_POST(self):
        cmd, param = parse_request_line(self.requestline)
        repo = None
        body = None

        if not cmd:
            cmd = self.headers.get('X-GitHub-Event')

        if not cmd:
            message = {'message': 'Request not found'}
            self.reply(message, code=400)
            return

        if cmd not in cmd_post:
            message = {'message': 'Request not found'}
            self.reply(message, code=404, cmd=cmd)
            return

        if cmd in cmd_post_hr_ignored:
            message = {'message': 'Request ignored'}
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

            if 'repository' in body:
                if 'full_name' in body['repository']:
                    repo = body['repository']['full_name']
        else:
            if 'repo' in param:
                repo = param['repo']

        if not repo:
            message = {'message': 'Repository not defined'}
            self.reply(message, code=400, cmd=cmd)
            return

        repo_hash = hash(repo) % ((sys.maxsize + 1) * 2)

        if repo_hash not in config:
            message = {'message': 'Repository not found'}
            self.reply(message, code=404, cmd=cmd, repo=repo)
            return

        if cmd == 'ping':
            message = {'message': 'Pong'}
            self.reply(message, cmd=cmd, repo=repo)
            return

        if cmd == 'sync':
            sync_list = prepare_list(None, repo_hash)
            message, code = sync(sync_list, repo_hash)
            self.reply(message, code=code, cmd=cmd, repo=repo)
            return

        if cmd == 'push':
            if body['ref'].split('/')[:3][2] != 'master':
                message = {'message': 'Branch not master, ignored'}
                self.reply(message, cmd=cmd, repo=repo)
                return

            sync_list = prepare_list(body, repo_hash)
            if not sync_list:
                message = {'message': 'Files in commit not match config'}
                self.reply(message, cmd=cmd, repo=repo)
                return
            else:
                message, code = sync(sync_list, repo_hash)
                self.reply(message, code=code, cmd=cmd, repo=repo)
                return

        message = {'message': 'Hook not found'}
        self.reply(message, code=404, cmd=cmd, repo=repo)
        return

    def log_message(self, format, *args):
        return

    def reply(self, message=None, silent=False, code=200, cmd=None, repo=None):
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
    parser.add_argument('--user', dest='user', default='fw-ops', help='github user (default: fw-ops)',
                        action="store")
    parser.add_argument('--email', dest='email', default='fiware.bot@gmail.com',
                        help='github user email (default: fiware.bot@gmail.com)', action="store")
    parser.add_argument('--threads', dest='threads', default=4, help='threads to start (default: 4)',
                        action="store")
    parser.add_argument('--socks', dest='socks', default=2, help='socks to start (default: 2)',  action="store")

    args = parser.parse_args()

    user = args.user
    email = args.email

    address = (args.ip, args.port)
    version_path = os.path.split(os.path.abspath(__file__))[0] + '/version'
    test_file = 'api1.apib'
    test_repo = 'FIWARE-Tests/apispectransformer-source'

    event = threading.BoundedSemaphore(1)

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

    if not os.path.isfile(args.config_path):
        print(jsn.dumps({'message': 'Config file not found', 'code': 500, 'cmd': 'start'}, indent=2))
        config_file = None
        sys.exit(1)
    try:
        with open(args.config_path) as f:
            cfg = jsn.load(f)
    except ValueError:
        print(jsn.dumps({'message': 'Unsupported config type', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    version = dict()
    if not os.path.isfile(version_path):
        print(jsn.dumps({'message': 'Version file not found', 'code': 500, 'cmd': 'start'}, indent=2))
        version_file = None
        sys.exit(1)
    try:
        with open(version_path) as f:
            version_file = f.read().split('\n')
            version['build'] = version_file[0]
            version['commit'] = version_file[1]
    except IndexError:
        print(jsn.dumps({'message': 'Unsupported version file type', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    print(jsn.dumps({'message': 'Loading config', 'code': 200, 'cmd': 'start'}, indent=2))

    try:
        dst_format = cfg['format']
        dst_branches = cfg['branches']
        config = dict()
        for r in cfg['repositories']:
            repository = get_hash(r['source'])
            config[repository] = dict()
            config[repository]['source'] = r['source']
            config[repository]['target'] = r['target']
            config[repository]['files'] = dict()
            for f in r['files']:
                fl = get_hash(f['source'])
                config[repository]['files'][fl] = dict()
                config[repository]['files'][fl]['source'] = f['source']
                config[repository]['files'][fl]['target'] = f['target']
                config[repository]['files'][fl]['transform'] = f['transform']
    except KeyError:
        print(jsn.dumps({'message': 'Config is not correct', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    if len(config) == 0:
        print(jsn.dumps({'message': 'Repositories list is empty', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)
    if len(dst_branches) == 0:
        print(jsn.dumps({'message': 'Branches not defined', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(args.socks)

    [Thread(i) for i in range(args.threads)]

    print(jsn.dumps({'message': 'Service started', 'code': 200}, indent=2))

    while True:
        time.sleep(9999)
