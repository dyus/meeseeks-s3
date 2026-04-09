#!/usr/bin/env python3
"""
Скрипт для выполнения success тестов ListObjectVersions API
"""

import subprocess
import sys
import os
import json
import time
import tempfile
from datetime import datetime

BUCKET_NAME = 'test-dagm-bucket-listversioning'

# Объекты для создания
OBJECTS = ['a', 'aa', 'a/as', 'a/', 'a/f', 'b', 'b/', 'c', 'd']

# Объекты, для которых нужно создать 2 версии
OBJECTS_WITH_VERSIONS = ['a', 'aa', 'a/as', 'a/', 'b', 'b/', 'a/f']

def run_command(cmd, description):
    """Выполняет команду AWS CLI с --debug и логирует результат"""
    output_lines = []
    output_lines.append(f"\n{'='*80}")
    output_lines.append(f"# {description}")
    output_lines.append(f"{'='*80}")
    output_lines.append(f"Команда: {' '.join(cmd)}")
    output_lines.append(f"{'='*80}\n")
    
    # Выполняем команду с --debug
    full_cmd = cmd + ['--debug']
    
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            check=False  # Не падаем на ошибках, чтобы продолжить тесты
        )
        
        # Добавляем stdout и stderr в вывод
        output_lines.append(result.stdout)
        if result.stderr:
            output_lines.append(result.stderr)
        
        output_text = '\n'.join(output_lines)
        # Выводим в stdout для перенаправления в файл
        print(output_text, flush=True)
        
        return result.returncode == 0, output_text
    except Exception as e:
        error_text = f"Ошибка выполнения команды: {e}"
        output_lines.append(error_text)
        output_text = '\n'.join(output_lines)
        print(output_text, flush=True)
        return False, output_text

def main():
    endpoint_url = os.environ.get('S3_ENDPOINT_URL', '')
    region = os.environ.get('AWS_REGION', 'us-east-1')
    
    # Базовые параметры для AWS CLI
    base_args = []
    if endpoint_url:
        base_args.extend(['--endpoint-url', endpoint_url])
    if region:
        base_args.extend(['--region', region])
    
    header = f"Начало выполнения тестов: {datetime.now()}\n"
    header += f"ENDPOINT_URL: {endpoint_url}\n"
    header += f"REGION: {region}\n"
    header += f"BUCKET: {BUCKET_NAME}\n"
    print(header, flush=True)
    
    all_output = [header]
    
    # Подготовка: Создание бакета и объектов
    print("\n" + "="*80)
    print("ПОДГОТОВКА: Создание бакета и объектов")
    print("="*80)
    
    # 1. Создать бакет
    success, output = run_command(
        ['aws', 's3api', 'create-bucket', '--bucket', BUCKET_NAME] + base_args,
        "1. Создать бакет test-dagm-bucket-listversioning"
    )
    all_output.append(output)
    
    # 2. Создать все объекты
    for obj_key in OBJECTS:
        # Создаем временный файл с содержимым
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(f"Content for {obj_key}\n")
            temp_file = f.name
        
        try:
            success, output = run_command(
                ['aws', 's3api', 'put-object', '--bucket', BUCKET_NAME, '--key', obj_key, '--body', temp_file] + base_args,
                f"2. Создать объект {obj_key}"
            )
            all_output.append(output)
        finally:
            os.unlink(temp_file)
    
    # 3. Включить версионирование
    success, output = run_command(
        ['aws', 's3api', 'put-bucket-versioning',
         '--bucket', BUCKET_NAME,
         '--versioning-configuration', 'Status=Enabled'] + base_args,
        "3. Включить версионирование в бакете"
    )
    all_output.append(output)
    
    # 4. Добавить 2 версии для указанных объектов
    for obj_key in OBJECTS_WITH_VERSIONS:
        # Создаем вторую версию
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(f"Version 2 content for {obj_key}\n")
            temp_file = f.name
        
        try:
            success, output = run_command(
                ['aws', 's3api', 'put-object', '--bucket', BUCKET_NAME, '--key', obj_key, '--body', temp_file] + base_args,
                f"4. Добавить вторую версию для объекта {obj_key}"
            )
            all_output.append(output)
        finally:
            os.unlink(temp_file)
        
        # Создаем третью версию
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(f"Version 3 content for {obj_key}\n")
            temp_file = f.name
        
        try:
            success, output = run_command(
                ['aws', 's3api', 'put-object', '--bucket', BUCKET_NAME, '--key', obj_key, '--body', temp_file] + base_args,
                f"4. Добавить третью версию для объекта {obj_key}"
            )
            all_output.append(output)
        finally:
            os.unlink(temp_file)
    
    # Небольшая задержка для синхронизации
    time.sleep(1)
    
    # Тест 1: Запросить листинг всех версий объектов
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions', '--bucket', BUCKET_NAME] + base_args,
        "Тест 1: Запросить листинг всех версий объектов"
    )
    all_output.append(output)
    
    # Тест 2.1: Запросить листинг версий с keyMarker a и несуществующей версией и лимитом 1
    nonexistent_version_id = 'nonexistent-version-id-12345'
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions',
         '--bucket', BUCKET_NAME,
         '--key-marker', 'a',
         '--version-id-marker', nonexistent_version_id,
         '--max-keys', '1'] + base_args,
        "Тест 2.1: Запросить листинг версий с keyMarker a и несуществующей версией и лимитом 1"
    )
    all_output.append(output)
    
    # Тест 2.2: Запросить листинг версий с keyMarker a и несуществующей версией в похожем формате и лимитом 1
    nonexistent_version_id_similar_format = 'Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R'
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions',
         '--bucket', BUCKET_NAME,
         '--key-marker', 'a',
         '--version-id-marker', nonexistent_version_id_similar_format,
         '--max-keys', '1'] + base_args,
        "Тест 2.2: Запросить листинг версий с keyMarker a и несуществующей версией в похожем формате (Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R) и лимитом 1"
    )
    all_output.append(output)
    
    # Тест 3: Запросить листинг версий с keyMarker a и существующей не последней версией и лимитом 1
    # Сначала получаем версии объекта 'a', чтобы найти не последнюю версию
    # Выполняем без --debug для получения чистого JSON
    result = subprocess.run(
        ['aws', 's3api', 'list-object-versions', '--bucket', BUCKET_NAME, '--prefix', 'a'] + base_args,
        capture_output=True,
        text=True,
        check=False
    )
    
    version_id = None
    if result.returncode == 0:
        try:
            json_data = json.loads(result.stdout)
            versions = json_data.get('Versions', [])
            if len(versions) > 1:
                # Берем последнюю версию в списке (самую старую)
                version_id = versions[-1]['VersionId']
            elif len(versions) == 1:
                version_id = versions[0]['VersionId']
        except Exception:
            pass
    
    if not version_id:
        version_id = 'unknown-version-id'
    
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions',
         '--bucket', BUCKET_NAME,
         '--key-marker', 'a',
         '--version-id-marker', version_id,
         '--max-keys', '1'] + base_args,
        "Тест 3: Запросить листинг версий с keyMarker a и существующей не последней версией и лимитом 1"
    )
    all_output.append(output)
    
    # Тест 4: Запросить листинг версий с делимитером / и таким лимитом так чтобы NextKeyMarker был с делимитером
    # Пробуем разные значения max-keys, пока не получим NextKeyMarker с делимитером
    max_keys_with_delimiter = None
    for test_max_keys in range(1, 21):
        # Выполняем без --debug для получения чистого JSON
        result = subprocess.run(
            ['aws', 's3api', 'list-object-versions',
             '--bucket', BUCKET_NAME,
             '--delimiter', '/',
             '--max-keys', str(test_max_keys)] + base_args,
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            try:
                json_data = json.loads(result.stdout)
                if json_data.get('IsTruncated'):
                    next_key_marker = json_data.get('NextKeyMarker', '')
                    if next_key_marker and next_key_marker.endswith('/'):
                        max_keys_with_delimiter = test_max_keys
                        break
            except Exception:
                pass
    
    if max_keys_with_delimiter is None:
        max_keys_with_delimiter = 3
    
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions',
         '--bucket', BUCKET_NAME,
         '--delimiter', '/',
         '--max-keys', str(max_keys_with_delimiter)] + base_args,
        f"Тест 4: Запросить листинг версий с делимитером / и лимитом {max_keys_with_delimiter} так чтобы NextKeyMarker был с делимитером"
    )
    all_output.append(output)
    
    # Тест 5: Запросить листинг версий с делимитером / и таким лимитом так чтобы NextKeyMarker был без делимитера
    # Пробуем разные значения max-keys, пока не получим NextKeyMarker без делимитера
    max_keys_without_delimiter = None
    for test_max_keys in range(1, 21):
        # Выполняем без --debug для получения чистого JSON
        result = subprocess.run(
            ['aws', 's3api', 'list-object-versions',
             '--bucket', BUCKET_NAME,
             '--delimiter', '/',
             '--max-keys', str(test_max_keys)] + base_args,
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            try:
                json_data = json.loads(result.stdout)
                if json_data.get('IsTruncated'):
                    next_key_marker = json_data.get('NextKeyMarker', '')
                    if next_key_marker and not next_key_marker.endswith('/'):
                        max_keys_without_delimiter = test_max_keys
                        break
            except Exception:
                pass
    
    if max_keys_without_delimiter is None:
        max_keys_without_delimiter = 1
    
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions',
         '--bucket', BUCKET_NAME,
         '--delimiter', '/',
         '--max-keys', str(max_keys_without_delimiter)] + base_args,
        f"Тест 5: Запросить листинг версий с делимитером / и лимитом {max_keys_without_delimiter} так чтобы NextKeyMarker был без делимитера"
    )
    all_output.append(output)
    
    # Тест 6: Запросить листинг версий с несуществующим keyMarker ab и пустой версией и лимитом 1
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions',
         '--bucket', BUCKET_NAME,
         '--key-marker', 'ab',
         '--version-id-marker', '',
         '--max-keys', '1'] + base_args,
        "Тест 6: Запросить листинг версий с несуществующим keyMarker ab и пустой версией и лимитом 1"
    )
    all_output.append(output)
    
    # Тест 7: Запросить листинг версий с несуществующим keyMarker ab и версией Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R и лимитом 1
    nonexistent_version_id = 'Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R'
    success, output = run_command(
        ['aws', 's3api', 'list-object-versions',
         '--bucket', BUCKET_NAME,
         '--key-marker', 'ab',
         '--version-id-marker', nonexistent_version_id,
         '--max-keys', '1'] + base_args,
        "Тест 7: Запросить листинг версий с несуществующим keyMarker ab и версией Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R и лимитом 1"
    )
    all_output.append(output)
    
    footer = f"\n{'='*80}\n"
    footer += f"Завершение выполнения тестов: {datetime.now()}\n"
    footer += f"{'='*80}\n"
    print(footer, flush=True)
    
    # Сохраняем весь вывод в файл
    log_filename = 'test_list_object_versions.log'
    with open(log_filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_output))
        f.write(footer)
    
    print(f"✓ Результаты сохранены в {log_filename}", flush=True)

if __name__ == '__main__':
    main()
