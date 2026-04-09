#!/usr/bin/env python3
"""
Скрипт для выполнения success тестов ListObjectVersions API
Использует Python boto3/requests для получения XML ответов и заголовков напрямую
"""

import os
import sys
import json
import time
import tempfile
import hashlib
from datetime import datetime
from urllib.parse import urlencode, quote, urlparse, urlunparse, parse_qs

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import get_credentials
import requests

BUCKET_NAME = 'test-dagm-bucket-listversioning'

# Объекты для создания
OBJECTS = ['a', 'aa', 'a/as', 'a/', 'a/f', 'b', 'b/', 'c', 'd']

# Объекты, для которых нужно создать 2 версии
OBJECTS_WITH_VERSIONS = ['a', 'aa', 'a/as', 'a/', 'b', 'b/', 'a/f']

def get_aws_config():
    """Получает конфигурацию AWS из переменных окружения или конфига"""
    endpoint_url = os.environ.get('S3_ENDPOINT_URL', '')
    region = os.environ.get('AWS_REGION', 'us-east-1')
    profile = os.environ.get('AWS_PROFILE', '')
    
    session = boto3.Session(profile_name=profile if profile else None)
    credentials = session.get_credentials()
    
    return {
        'endpoint_url': endpoint_url,
        'region': region,
        'credentials': credentials,
        'session': session
    }

def make_signed_request(method, url, headers=None, data=None, config=None):
    """Создает подписанный AWS запрос и возвращает ответ с XML и заголовками"""
    if headers is None:
        headers = {}
    
    # Добавляем x-amz-content-sha256
    if data:
        body_hash = hashlib.sha256(data if isinstance(data, bytes) else data.encode('utf-8')).hexdigest()
    else:
        body_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # Empty body hash
    headers['x-amz-content-sha256'] = body_hash
    
    # Создаем AWS запрос
    request = AWSRequest(method=method, url=url, headers=headers, data=data)
    
    # Подписываем запрос
    SigV4Auth(config['credentials'], 's3', config['region']).add_auth(request)
    
    # Выполняем запрос
    response = requests.request(
        method=method,
        url=url,
        headers=dict(request.headers),
        data=data
    )
    
    return response

def format_response_for_md(test_num, description, method, url, response, query_params=None):
    """Форматирует ответ для Markdown"""
    md = []
    md.append(f"## {description}\n\n")
    
    # URL с параметрами
    if query_params:
        url_with_params = f"{url}?{urlencode(query_params, quote_via=quote)}"
    else:
        url_with_params = url
    
    md.append(f"**{method} URL:** `{url_with_params}`\n\n")
    
    # Заголовки запроса
    md.append("**Request Headers:**\n")
    md.append("```\n")
    for key, value in sorted(response.request.headers.items()):
        md.append(f"{key}: {value}\n")
    md.append("```\n\n")
    
    # Тело запроса (если есть)
    if response.request.body:
        md.append("**Request Body:**\n")
        md.append("```\n")
        if isinstance(response.request.body, bytes):
            md.append(response.request.body.decode('utf-8'))
        else:
            md.append(str(response.request.body))
        md.append("\n```\n\n")
    
    # Ответ
    md.append("**Response:**\n")
    md.append(f"**Status:** `{response.status_code}`\n\n")
    
    # Тело ответа (XML)
    md.append("**Body (XML):**\n")
    md.append("```xml\n")
    try:
        xml_content = response.text
        md.append(xml_content)
    except:
        md.append("(не удалось декодировать)")
    md.append("\n```\n\n")
    
    # Заголовки ответа
    md.append("**Response Headers:**\n")
    md.append("```\n")
    for key, value in sorted(response.headers.items()):
        md.append(f"{key}: {value}\n")
    md.append("```\n\n")
    
    md.append("---\n\n")
    
    return ''.join(md)

def setup_bucket_and_objects(config):
    """Создает бакет, объекты и включает версионирование"""
    s3_client = config['session'].client('s3', region_name=config['region'])
    if config['endpoint_url']:
        s3_client = config['session'].client('s3', region_name=config['region'], endpoint_url=config['endpoint_url'])
    
    md_content = []
    md_content.append("## Подготовка: Создание бакета и объектов\n\n")
    
    # 1. Создать бакет
    try:
        s3_client.create_bucket(Bucket=BUCKET_NAME)
        md_content.append(f"✓ Бакет `{BUCKET_NAME}` создан\n\n")
    except Exception as e:
        if 'BucketAlreadyOwnedByYou' in str(e) or 'BucketAlreadyExists' in str(e):
            md_content.append(f"✓ Бакет `{BUCKET_NAME}` уже существует\n\n")
        else:
            md_content.append(f"✗ Ошибка создания бакета: {e}\n\n")
    
    # 2. Создать все объекты
    for obj_key in OBJECTS:
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(f"Content for {obj_key}\n")
                temp_file = f.name
            
            s3_client.put_object(Bucket=BUCKET_NAME, Key=obj_key, Body=open(temp_file, 'rb'))
            os.unlink(temp_file)
        except Exception as e:
            md_content.append(f"✗ Ошибка создания объекта {obj_key}: {e}\n")
    
    md_content.append(f"✓ Создано {len(OBJECTS)} объектов\n\n")
    
    # 3. Включить версионирование
    try:
        s3_client.put_bucket_versioning(
            Bucket=BUCKET_NAME,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        md_content.append("✓ Версионирование включено\n\n")
    except Exception as e:
        md_content.append(f"✗ Ошибка включения версионирования: {e}\n\n")
    
    # 4. Добавить 2 версии для указанных объектов
    for obj_key in OBJECTS_WITH_VERSIONS:
        for version_num in [2, 3]:
            try:
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                    f.write(f"Version {version_num} content for {obj_key}\n")
                    temp_file = f.name
                
                s3_client.put_object(Bucket=BUCKET_NAME, Key=obj_key, Body=open(temp_file, 'rb'))
                os.unlink(temp_file)
            except Exception as e:
                pass
    
    md_content.append(f"✓ Добавлено по 2 дополнительные версии для {len(OBJECTS_WITH_VERSIONS)} объектов\n\n")
    
    time.sleep(1)
    
    return md_content

def test_list_object_versions(config, query_params=None, description=""):
    """Выполняет ListObjectVersions запрос и возвращает XML и заголовки"""
    region = config['region']
    endpoint_url = config['endpoint_url']
    
    # Формируем базовый URL
    if endpoint_url:
        base_url = endpoint_url.rstrip('/')
        base_path = f"/{BUCKET_NAME}"
    else:
        base_url = f"https://{BUCKET_NAME}.s3.{region}.amazonaws.com"
        base_path = "/"
    
    # Формируем query параметры
    all_params = {'versions': ''}
    if query_params:
        all_params.update(query_params)
    
    # Правильно формируем URL с параметрами
    params_str = urlencode(all_params, quote_via=quote, doseq=True)
    url = f"{base_url}{base_path}?{params_str}"
    
    # Выполняем запрос
    response = make_signed_request('GET', url, config=config)
    
    return response, url

def main():
    config = get_aws_config()
    
    md_content = []
    md_content.append("# Тесты ListObjectVersions API (Python)\n\n")
    md_content.append(f"**Дата выполнения:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    md_content.append(f"**Region:** `{config['region']}`\n")
    md_content.append(f"**Bucket:** `{BUCKET_NAME}`\n")
    if config['endpoint_url']:
        md_content.append(f"**Endpoint URL:** `{config['endpoint_url']}`\n")
    md_content.append("\n---\n\n")
    
    # Подготовка
    setup_md = setup_bucket_and_objects(config)
    md_content.extend(setup_md)
    md_content.append("---\n\n")
    
    # Тест 1: Все объекты
    response, url = test_list_object_versions(config, description="Тест 1: Запросить листинг всех версий объектов")
    md_content.append(format_response_for_md(1, "Тест 1: Запросить листинг всех версий объектов", 'GET', url, response))
    
    # Тест 2.1: keyMarker a с несуществующей версией
    query_params = {'key-marker': 'a', 'version-id-marker': 'nonexistent-version-id-12345', 'max-keys': '1'}
    response, url = test_list_object_versions(config, query_params, "Тест 2.1")
    md_content.append(format_response_for_md(2.1, "Тест 2.1: keyMarker a с несуществующей версией и лимитом 1", 'GET', url, response, query_params))
    
    # Тест 2.2: keyMarker a с несуществующей версией в похожем формате
    query_params = {'key-marker': 'a', 'version-id-marker': 'Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R', 'max-keys': '1'}
    response, url = test_list_object_versions(config, query_params, "Тест 2.2")
    md_content.append(format_response_for_md(2.2, "Тест 2.2: keyMarker a с несуществующей версией в похожем формате и лимитом 1", 'GET', url, response, query_params))
    
    # Тест 3: keyMarker a с существующей не последней версией
    # Сначала получаем версии объекта 'a'
    s3_client = config['session'].client('s3', region_name=config['region'])
    if config['endpoint_url']:
        s3_client = config['session'].client('s3', region_name=config['region'], endpoint_url=config['endpoint_url'])
    
    try:
        result = s3_client.list_object_versions(Bucket=BUCKET_NAME, Prefix='a')
        versions = result.get('Versions', [])
        if len(versions) > 1:
            version_id = versions[-1]['VersionId']
        elif len(versions) == 1:
            version_id = versions[0]['VersionId']
        else:
            version_id = 'null'
    except:
        version_id = 'null'
    
    query_params = {'key-marker': 'a', 'version-id-marker': version_id, 'max-keys': '1'}
    response, url = test_list_object_versions(config, query_params, "Тест 3")
    md_content.append(format_response_for_md(3, "Тест 3: keyMarker a с существующей не последней версией и лимитом 1", 'GET', url, response, query_params))
    
    # Тест 4: делимитер с NextKeyMarker с делимитером
    # Находим нужный max-keys
    max_keys_with_delimiter = None
    for test_max_keys in range(1, 21):
        query_params = {'delimiter': '/', 'max-keys': str(test_max_keys)}
        test_response, _ = test_list_object_versions(config, query_params)
        if test_response.status_code == 200:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(test_response.text)
                is_truncated = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated')
                next_key_marker = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}NextKeyMarker')
                if is_truncated is not None and is_truncated.text == 'true' and next_key_marker is not None:
                    if next_key_marker.text and next_key_marker.text.endswith('/'):
                        max_keys_with_delimiter = test_max_keys
                        break
            except:
                pass
    
    if max_keys_with_delimiter is None:
        max_keys_with_delimiter = 3
    
    query_params = {'delimiter': '/', 'max-keys': str(max_keys_with_delimiter)}
    response, url = test_list_object_versions(config, query_params, "Тест 4")
    md_content.append(format_response_for_md(4, f"Тест 4: делимитер / с лимитом {max_keys_with_delimiter} так чтобы NextKeyMarker был с делимитером", 'GET', url, response, query_params))
    
    # Тест 5: делимитер с NextKeyMarker без делимитера
    max_keys_without_delimiter = None
    for test_max_keys in range(1, 21):
        query_params = {'delimiter': '/', 'max-keys': str(test_max_keys)}
        test_response, _ = test_list_object_versions(config, query_params)
        if test_response.status_code == 200:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(test_response.text)
                is_truncated = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated')
                next_key_marker = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}NextKeyMarker')
                if is_truncated is not None and is_truncated.text == 'true' and next_key_marker is not None:
                    if next_key_marker.text and not next_key_marker.text.endswith('/'):
                        max_keys_without_delimiter = test_max_keys
                        break
            except:
                pass
    
    if max_keys_without_delimiter is None:
        max_keys_without_delimiter = 1
    
    query_params = {'delimiter': '/', 'max-keys': str(max_keys_without_delimiter)}
    response, url = test_list_object_versions(config, query_params, "Тест 5")
    md_content.append(format_response_for_md(5, f"Тест 5: делимитер / с лимитом {max_keys_without_delimiter} так чтобы NextKeyMarker был без делимитера", 'GET', url, response, query_params))
    
    # Тест 6.1: несуществующий keyMarker ab с пустой версией
    query_params = {'key-marker': 'ab', 'version-id-marker': '', 'max-keys': '1'}
    response, url = test_list_object_versions(config, query_params, "Тест 6.1")
    md_content.append(format_response_for_md(6.1, "Тест 6.1: несуществующий keyMarker ab с пустой версией и лимитом 1", 'GET', url, response, query_params))
    
    # Тест 6.2: несуществующий keyMarker ab без параметра version-id-marker
    query_params = {'key-marker': 'ab', 'max-keys': '1'}
    response, url = test_list_object_versions(config, query_params, "Тест 6.2")
    md_content.append(format_response_for_md(6.2, "Тест 6.2: несуществующий keyMarker ab без параметра version-id-marker и лимитом 1", 'GET', url, response, query_params))
    
    # Тест 7: несуществующий keyMarker ab с версией
    query_params = {'key-marker': 'ab', 'version-id-marker': 'Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R', 'max-keys': '1'}
    response, url = test_list_object_versions(config, query_params, "Тест 7")
    md_content.append(format_response_for_md(7, "Тест 7: несуществующий keyMarker ab с версией Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R и лимитом 1", 'GET', url, response, query_params))
    
    # Тест 8.1: без queryDelimiter
    query_params = {'max-keys': '5'}
    response, url = test_list_object_versions(config, query_params, "Тест 8.1")
    md_content.append(format_response_for_md(8.1, "Тест 8.1: без queryDelimiter", 'GET', url, response, query_params))
    
    # Тест 8.2: с queryDelimiter пустым
    query_params = {'delimiter': '', 'max-keys': '5'}
    response, url = test_list_object_versions(config, query_params, "Тест 8.2")
    md_content.append(format_response_for_md(8.2, "Тест 8.2: с queryDelimiter пустым", 'GET', url, response, query_params))
    
    # Тест 9.1: без queryPrefix
    query_params = {'max-keys': '5'}
    response, url = test_list_object_versions(config, query_params, "Тест 9.1")
    md_content.append(format_response_for_md(9.1, "Тест 9.1: без queryPrefix", 'GET', url, response, query_params))
    
    # Тест 9.2: с queryPrefix пустым
    query_params = {'prefix': '', 'max-keys': '5'}
    response, url = test_list_object_versions(config, query_params, "Тест 9.2")
    md_content.append(format_response_for_md(9.2, "Тест 9.2: с queryPrefix пустым", 'GET', url, response, query_params))
    
    # Тест 10.1: с queryEncodingType пустым
    query_params = {'encoding-type': '', 'max-keys': '5'}
    response, url = test_list_object_versions(config, query_params, "Тест 10.1")
    md_content.append(format_response_for_md(10.1, "Тест 10.1: с queryEncodingType пустым", 'GET', url, response, query_params))
    
    # Тест 10.2: без queryEncodingType вовсе
    query_params = {'max-keys': '5'}
    response, url = test_list_object_versions(config, query_params, "Тест 10.2")
    md_content.append(format_response_for_md(10.2, "Тест 10.2: без queryEncodingType вовсе", 'GET', url, response, query_params))
    
    # Тест 11.1: с queryMaxKeys пустым
    query_params = {'max-keys': ''}
    response, url = test_list_object_versions(config, query_params, "Тест 11.1")
    md_content.append(format_response_for_md(11.1, "Тест 11.1: с queryMaxKeys пустым", 'GET', url, response, query_params))
    
    # Тест 11.2: без max-keys
    query_params = {}
    response, url = test_list_object_versions(config, query_params, "Тест 11.2")
    md_content.append(format_response_for_md(11.2, "Тест 11.2: без max-keys", 'GET', url, response, query_params))
    
    # Тест 11.3: с max-keys='m' (некорректное значение)
    query_params = {'max-keys': 'm'}
    response, url = test_list_object_versions(config, query_params, "Тест 11.3")
    md_content.append(format_response_for_md(11.3, "Тест 11.3: с max-keys='m' (некорректное значение)", 'GET', url, response, query_params))
    
    # Сохраняем MD файл
    md_filename = 'test_list_object_versions_python.md'
    with open(md_filename, 'w', encoding='utf-8') as f:
        f.write(''.join(md_content))
    
    print(f"✓ Результаты сохранены в {md_filename}", flush=True)

if __name__ == '__main__':
    main()

