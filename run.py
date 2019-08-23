#!/usr/bin/python3
# -*- coding: utf-8 -*-

from aiohttp import web, ClientSession, ClientConnectorError
from argparse import ArgumentParser
from base64 import b64encode
from copy import deepcopy
from logging import error, getLogger
from os import path, environ
from uvloop import EventLoopPolicy
from yajl import dumps, loads
import asyncio


config = dict()
locks = dict()
version = dict()
routes = web.RouteTableDef()
api_url = 'https://api.github.com/'
token_github = None
token_apimatic = ''
user = None
email = None
spec = None
branches = list()
sem_apimatic = None
sem_github = None


event_ignored = ['check_run', 'check_suite', 'commit_comment', 'deployment', 'deployment_status', 'status', 'gollum',
                 'installation', 'installation_repositories', 'issue_comment', 'issues', 'label', 'member', 'fork',
                 'membership', 'marketplace_purchase', 'milestone', 'organization', 'org_block', 'page_build', 'create',
                 'project_card', 'project_column', 'project', 'public', 'pull_request', 'pull_request_review_comment',
                 'pull_request_review', 'repository', 'watch', 'team_add', 'repository_vulnerability_alert', 'team',
                 'delete', 'release', 'star', 'deploy_key']

event_accepted = ['push']


@routes.get('/ping')
async def get_handler(request):
    return web.Response(text = 'pong\n')


@routes.get('/version')
async def get_handler(request):
    return web.Response(text=version)


@routes.post('/apimatic')
async def get_handler(request):
    return web.Response(text='Temporary disabled\n')


@routes.post('/sync')
async def get_handler(request):
    data = {'repository': {'full_name': ''},
            'commits': [{'modified': []}],
            "ref": "refs/heads/master"}

    try:
        repository = request.rel_url.query['id']
    except KeyError:
        return web.Response(text='Wrong payload\n', status=400)

    data['repository']['full_name'] = repository
    data['commits'][0]['modified'] = deepcopy(config[repository]['files'])

    return await synchronize(data)


@routes.post('/')
async def post_handler(request):
    try:
        event = request.headers['X-GitHub-Event']
    except KeyError:
        return web.HTTPBadRequest()

    if event == 'ping':
        return web.Response(text='pong\n')

    if event in event_ignored:
        return web.Response(text='event in the ignored list\n')

    if event not in event_accepted:
        error('Unknown event, %s', event)
        return web.Response(text="Unknown event" + event + '\n', status=400)

    data = (await request.read()).decode('UTF-8')

    try:
        data = loads(data)
    except ValueError:
        error('Bad request, %s', data)
        return web.HTTPBadRequest()

    return await synchronize(data)


async def get_file(source_file, source_repository, session):
    repository = source_repository
    fl = source_file
    url = 'https://raw.githubusercontent.com/' + repository + '/master/' + fl
    try:
        async with session.get(url) as response:
            status = response.status
            text = await response.text()
    except ClientConnectorError:
        text = 'File ' + fl + ' from ' + repository + ' fetching failed due to the connection problem\n'
        return web.Response(text=text, status=502)
    except TimeoutError:
        text = 'File ' + fl + ' from ' + repository + ' fetching  failed due to the timeout\n'
        return web.Response(text=text, status=504)
    except Exception as exception:
        error('File fetching, %s, %s, %s', exception, repository, fl)
        return web.HTTPInternalServerError()

    if status != 200:
        text = 'File ' + fl + ' from ' + repository + ' fetching failed due to the: ' + text + '\n'
        return web.Response(text=text, status = status)

    return {'file': fl, 'value': bytes(text, 'UTF-8')}


async def get_file_sha(source_file, source_repository, branch, session):
    repository = config[source_repository]['target']
    fl = config[source_repository]['files'][source_file]['target']
    url = 'https://api.github.com/repos/' + repository + '/contents/' + fl + '?ref=' + branch
    try:
        async with session.get(url) as response:
            status = response.status
            text = await response.text()
    except ClientConnectorError:
        text = 'File ' + fl + ' from ' + repository + ' getting sha failed due to the connection problem\n'
        return web.Response(text=text, status=502)
    except TimeoutError:
        text = 'File ' + fl + ' from ' + repository + ' getting sha failed due to the timeout\n'
        return web.Response(text=text, status=504)
    except Exception as exception:
        error('File fetching, %s, %s, %s', exception, repository, fl)
        return web.HTTPInternalServerError()

    if status not in [200, 201, 404]:
        text = 'File ' + fl + ' from ' + repository + ' getting sha failed due to the: ' + text + '\n'
        return web.Response(text=text, status = status)

    if status in [200, 201]:
        text = loads(text)
        if 'sha' in text:
            return {'file': source_file, 'branch': branch, 'value': text['sha']}

    return {'file': source_file, 'branch': branch}


async def put_file(source_file, source_repository, source_data, branch, session):
    async with sem_github:
        return await put_file_one(source_file, source_repository, source_data, branch, session)


async def put_file_one(source_file, source_repository, source_data, branch, session):
    repository = config[source_repository]['target']
    fl = config[source_repository]['files'][source_file]['target']

    headers = {'Content-Type': 'application/json',
               'Authorization': 'token ' + token_github}

    data = {'message': 'autosync',
            'branch': branch,
            'content': source_data['body']}
    if 'sha' in source_data:
        data['sha'] = source_data['sha']

    url = 'https://api.github.com/repos/' + repository + '/contents/' + fl
    data = dumps(data)

    try:
        async with session.put(url, headers=headers, data=data) as response:
            status = response.status
            text = await response.text()
    except ClientConnectorError:
        text = 'File ' + fl + ' from ' + repository + ' pushing failed due to the connection problem\n'
        return web.Response(text=text, status=502)
    except TimeoutError:
        text = 'File ' + fl + ' from ' + repository + ' pushing failed due to the timeout\n'
        return web.Response(text=text, status=504)
    except Exception as exception:
        error('File pushing, %s, %s, %s', exception, repository, fl)
        return web.HTTPInternalServerError()

    if status not in [200, 201]:
        text = 'File ' + fl + ' from ' + repository + ' pushing failed due to the: ' + text + '\n'
        return web.Response(text=text, status = status)

    return {}


async def synchronize(data):
    result = list()
    tasks_get = list()
    # tasks_transform = list()

    try:
        repository = data['repository']['full_name'].lower()
        branch = data['ref'].split('/')[:3][2]
    except ValueError:
        error('Bad request, %s', data)
        return web.HTTPBadRequest()
    except KeyError:
        return web.Response(text='Wrong payload\n', status=400)

    if repository not in config:
        return web.Response(text='Repository not found in the config\n', status=404)

    if branch not in ['master']:
        return web.Response(text='Branch not in master\n')

    # filter files
    commits = list()
    if 'commits' in data:
        commits = data['commits']
    if 'head_commit' in data:
        commits.append(data['head_commit'])
    for commit in commits:
        if 'added' in commit:
            for item in commit['added']:
                if item in config[repository]['files']:
                    result.append(item)
        if 'modified' in commit:
            for item in commit['modified']:
                if item in config[repository]['files']:
                    result.append(item)
    result = list(set(result))

    async with ClientSession() as session:
        # get or transform file and create result array
        for item in result:
            if not config[repository]['files'][item]['transform']:
                task_get = asyncio.ensure_future(get_file(item, repository, session))
                tasks_get.append(task_get)
            #else:
            #    task_transform = asyncio.ensure_future(transform_file(item, repository, session))
            #    tasks_transform.append(task_transform)

        tmp_get = await asyncio.gather(*tasks_get)
        #tmp_transform = await asyncio.gather(*tasks_transform)
        result = dict()

        for item in tmp_get: #+ tmp_transform:
            if not isinstance(item, dict):
                return item
            else:
                result[item['file']] = dict()
                result[item['file']]['body'] = b64encode(item['value']).decode()

        tasks_get = list()
        tmp_get = list()

        # get file sha
        for item in result:
            for branch in branches:
                task_get = asyncio.ensure_future(get_file_sha(item, repository, branch, session))
                tasks_get.append(task_get)

        tmp_get = await asyncio.gather(*tasks_get)
        for item in tmp_get:
            if not isinstance(item, dict):
                return item
            else:
                result[item['file']]['branch'] = item['branch']
                if 'value' in item:
                    result[item['file']]['sha'] = item['value']

        tasks_get = list()
        tmp_get = list()

        # put
        for item in result:
            for branch in branches:
                task_get = asyncio.ensure_future(put_file(item, repository, result[item], branch, session))
                tasks_get.append(task_get)

        tmp_get = await asyncio.gather(*tasks_get)

        for item in tmp_get:
            if not isinstance(item, dict):
                return item

        return web.Response(text='Synchronized\n')


async def transform_file(source_file, source_repository, session):
    async with sem_apimatic:
        return await transform_file_one(source_file, source_repository, session)


async def transform_file_one(source_file, source_repository, session):
    fl = source_file
    repository = source_repository
    description = 'https://raw.githubusercontent.com/' + repository + '/master/' + fl
    url = 'https://apimatic.io/api/transform?format=' + specs + '&descriptionUrl=' + description

    try:
        async with session.get(url, headers={'Authorization': 'X-Auth-Key ' + token_apimatic}) as response:
            status = response.status
            text = await response.text()
    except ClientConnectorError:
        text = 'File ' + fl + ', ' + repository + ' transforming failed due to the connection problem\n'
        return web.Response(text=text, status=502)
    except TimeoutError:
        text = 'File ' + fl + ', ' + repository + ' transforming failed due to the timeout\n'
        return web.Response(text=text, status=504)
    except Exception as exception:
        error('File transforming, %s, %s, %s', exception, repository, fl)
        return web.HTTPInternalServerError()

    if status != 200:
        text = 'File ' + fl + ', ' + repository + ' transforming failed due to the: ' + text['message'] + '\n'
        return web.Response(text=text, status = status)

    return {'file': fl, 'value': text.encode()}


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('--ip', default='0.0.0.0', help='ip to use, default is 0.0.0.0')
    parser.add_argument('--port', default=8080, help='port to use, default is 8080')
    parser.add_argument('--config', default='/opt/config.json', help='path to config file, default is /opt/config.json')

    args = parser.parse_args()

    getLogger().setLevel(40)

    asyncio.set_event_loop_policy(EventLoopPolicy())

    sem_apimatic = asyncio.Semaphore(1)
    sem_github = asyncio.Semaphore(1)

    if 'TOKEN_GITHUB' in environ:
        token_github = environ['TOKEN_GITHUB']
    else:
        error('TOKEN_GITHUB not provided in the Env')
        exit(1)

#    if 'TOKEN_APIMATIC' in environ:
#        token_apimatic = environ['TOKEN_APIMATIC']
#    else:
#        error('TOKEN_APIMATIC not provided in the Env')
#        exit(1)

    version_path = './version'
    if not path.isfile(version_path):
        error('Version file not found')
        exit(1)
    try:
        with open(version_path) as f:
            version_file = f.read().split('\n')
            version['build'] = version_file[0]
            version['commit'] = version_file[1]
            version = dumps(version, indent=4)
    except IndexError:
        error('Unsupported version file type')
        exit(1)

    if not path.isfile(args.config):
        error('Config file not found')
        exit(1)
    try:
        with open(args.config) as file:
            temp = loads(file.read())
    except ValueError:
        error('Unsupported config type')
        exit(1)
    try:
        specs = temp['format']
        branches = deepcopy(temp['branches'])
        for element in temp['repositories']:
            source = element['source'].lower()
            config[source] = dict()
            config[source]['target'] = element['target']
            config[source]['lock'] = asyncio.Lock()
            config[source]['files'] = dict()
            for f in element['files']:
                config[source]['files'][f['source']] = dict()
                config[source]['files'][f['source']]['target'] = f['target']
                config[source]['files'][f['source']]['transform'] = f['transform']
    except KeyError:
        error('Config is not correct')
        exit(1)

    if len(config) == 0:
        error('Repository list is empty')
        exit(1)

    if len(branches) == 0:
        branches.append('master')

    app = web.Application()
    app.add_routes(routes)
    web.run_app(app, host=args.ip, port=args.port)
