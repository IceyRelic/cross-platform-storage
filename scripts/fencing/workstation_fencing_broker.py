# -*- coding: utf-8 -*-
# 【中文注释】用途：宿主隔离控制器：固定两台存储VM，认证后签发短期许可，持久消费请求并确认真实off。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
"""Two-VM lab: authenticated automatic peer off with durable fail-closed receipts."""
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import datetime, hashlib, hmac, http.server, json, math, os, re, socket, ssl, subprocess
import threading, time
from pathlib import Path
import verify_vmware_identity as identity

VMCLI = r'C:\Program Files (x86)\VMware\VMware Workstation\vmcli.exe'
VMRUN = r'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
LOCK = threading.Lock()
STATES = {'on', 'off', 'paused', 'suspended'}
POLICY = 'automatic_peer_challenge'


# 【中文注释】函数 parse_power：只接受成功查询中的唯一明确平台状态；缺少VM/未知输出不算off。
def parse_power(returncode, stdout):
    if returncode != 0:
        raise RuntimeError('native_query_failed')
    rows = re.findall(r'^PowerState: ([A-Za-z]+)\s*$', stdout, re.M)
    if len(rows) != 1 or rows[0] not in STATES:
        raise RuntimeError('native_state_unknown')
    return rows[0]


# 【中文注释】函数 status：查询本次目标的明确平台电源状态并校验身份；查询失败/未知/paused不算成功off。
def status(node, mapping):
    if node not in mapping:
        raise ValueError('target_denied')
    current = identity.vm_identity(node)
    pin = mapping[node]
    for key in ('path', 'bios_uuid', 'mac'):
        if current[key] != pin[key]:
            raise RuntimeError('identity_changed')
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p = subprocess.run([VMCLI, current['path'], 'Power', 'query'],
                       capture_output=True, timeout=15,
                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    state = parse_power(p.returncode, p.stdout.decode('utf-8', 'strict'))
    # Recheck the path and identity after the platform query, not only before it.
    after = identity.vm_identity(node)
    if any(after[k] != pin[k] for k in ('path', 'bios_uuid', 'mac')):
        raise RuntimeError('identity_changed')
    return {'node': node, 'power_state': state, 'bios_uuid': current['bios_uuid'],
            'mac': current['mac'], 'source': 'native_vmcli_power_query'}


# 【中文注释】函数 check_pair：只允许两个固定节点间的peer请求，拒绝自身、其它VM和非法nonce。
def check_pair(caller, node, nonce, mapping):
    if caller not in mapping or node not in mapping or caller == node:
        raise ValueError('off_pair_denied')
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('nonce_denied')


# 【中文注释】函数 receipt_root：确定受限消费记录目录，拒绝链接/非目录，保存重启后仍需遵守的状态。
def receipt_root(private):
    root = private / 'automatic-off-receipts'
    root.mkdir(exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('receipt_directory_denied')
    return root


# 【中文注释】函数 check_receipts：拒绝已消费请求；任何pending/uncertain或损坏记录阻断新的off。
def check_receipts(private, nonce):
    root = receipt_root(private)
    if (root / (nonce + '.json')).exists():
        raise ValueError('off_request_already_consumed')
    # ponytail: a two-VM lab scans durable receipts; high-volume controllers need a journal.
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[0-9a-f]{32}\.json', path.name):
            raise ValueError('receipt_store_invalid')
        row = json.loads(path.read_text(encoding='utf-8'))
        if (not isinstance(row, dict) or row.get('nonce') != path.stem or
                row.get('caller') not in ('stor-svc-01', 'stor-svc-02') or
                row.get('node') not in ('stor-svc-01', 'stor-svc-02') or
                row['caller'] == row['node']):
            raise ValueError('receipt_store_invalid')
        if row.get('phase') not in ('verified_off', 'cancelled_before_command'):
            raise ValueError('previous_off_unresolved')
        if row['phase'] == 'verified_off' and (
                row.get('native_command_exit') not in (None, 0) or
                row.get('confirmation_states', [])[-2:] != ['off', 'off']):
            raise ValueError('receipt_store_invalid')


# 【中文注释】函数 signed_permit：将caller、目标、nonce、会话和期限一起签名，不能换目标后复用许可。
def signed_permit(caller, node, nonce, permit, key):
    body = dict(permit, caller=caller, node=node, nonce=nonce)
    body.pop('signature', None)
    return hmac.new(key, json.dumps(body, sort_keys=True, separators=(',', ':')).encode(),
                    hashlib.sha256).hexdigest()


# 【中文注释】函数 prepare_off：认证调用者并检查平台身份，签发当前会话的短期peer off能力。
def prepare_off(caller, node, nonce, mapping, private, session, key):
    check_pair(caller, node, nonce, mapping)
    check_receipts(private, nonce)
    if status(caller, mapping)['power_state'] != 'on':
        raise ValueError('off_caller_not_on')
    row = status(node, mapping)
    now = time.monotonic()
    permit = {'session_id': session, 'created_monotonic': now, 'expires_monotonic': now + 120}
    permit['signature'] = signed_permit(caller, node, nonce, permit, key)
    return dict(row, permit=permit, operation='prepare_off')


# 【中文注释】函数 validate_permit：核对许可字段、当前会话、有限单调期限及签名，拒绝过期/篡改许可。
def validate_permit(caller, node, nonce, permit, session, key):
    if not isinstance(permit, dict) or set(permit) != {
            'session_id', 'created_monotonic', 'expires_monotonic', 'signature'}:
        raise ValueError('automatic_permit_schema_denied')
    if permit['session_id'] != session:
        raise ValueError('automatic_permit_session_denied')
    start, end = permit['created_monotonic'], permit['expires_monotonic']
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
           for v in (start, end)):
        raise ValueError('automatic_permit_time_denied')
    if not start <= time.monotonic() < end <= start + 120:
        raise ValueError('automatic_permit_expired')
    signature = permit['signature']
    if not isinstance(signature, str) or not re.fullmatch('[0-9a-f]{64}', signature):
        raise ValueError('automatic_permit_signature_denied')
    if not hmac.compare_digest(signature, signed_permit(caller, node, nonce, permit, key)):
        raise ValueError('automatic_permit_signature_denied')


# 【中文注释】函数 save_receipt：原子或独占写消费记录并刷盘；必须先持久消费，后执行真实电源动作。
def save_receipt(path, value, exclusive=False):
    if exclusive:
        with path.open('x', encoding='utf-8') as handle:
            json.dump(value, handle)
            handle.flush()
            # 【中文注释】刷盘该文件/状态，减少进程中断时只留下内存成功的风险。
            os.fsync(handle.fileno())
    else:
        temp = path.with_suffix('.tmp')
        with temp.open('x', encoding='utf-8') as handle:
            json.dump(value, handle)
            handle.flush()
            # 【中文注释】刷盘该文件/状态，减少进程中断时只留下内存成功的风险。
            os.fsync(handle.fileno())
        os.replace(temp, path)


# 【中文注释】函数 automatic_off：在全局锁内再次校验许可，持久消费后关机；不确定结果留阻断记录，明确off才成功。
def automatic_off(caller, node, nonce, permit, mapping, private, session, key):
    # Handler holds the same global lock for prepare/off/status, including opposite requests.
    check_pair(caller, node, nonce, mapping)
    validate_permit(caller, node, nonce, permit, session, key)
    check_receipts(private, nonce)
    if status(caller, mapping)['power_state'] != 'on':
        raise ValueError('off_caller_not_on')
    before = status(node, mapping)
    path = receipt_root(private) / (nonce + '.json')
    receipt = {'caller': caller, 'node': node, 'nonce': nonce, 'session_id': session,
               'phase': 'pending', 'time_local': datetime.datetime.now().isoformat()}
    save_receipt(path, receipt, exclusive=True)  # Consume durably before any native command.
    if time.monotonic() >= permit['expires_monotonic']:
        save_receipt(path, dict(receipt, phase='cancelled_before_command'))
        raise ValueError('automatic_permit_expired_before_command')
    command_exit = None
    observations = []
    try:
        deadline = time.monotonic() + 50
        if before['power_state'] != 'off':
            # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
            power = subprocess.run([VMRUN, '-T', 'ws', 'stop', mapping[node]['path'], 'hard'],
                capture_output=True, timeout=30,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            command_exit = power.returncode
            if command_exit != 0:
                raise RuntimeError('native_off_failed')
        while time.monotonic() < deadline:
            row = status(node, mapping)
            observations.append(row['power_state'])
            if observations[-2:] == ['off', 'off']:
                if status(caller, mapping)['power_state'] != 'on':
                    raise RuntimeError('off_caller_state_changed')
                save_receipt(path, dict(receipt, phase='verified_off',
                    native_command_exit=command_exit, confirmation_states=observations))
                return dict(row, operation='off', native_command_exit=command_exit,
                            confirmation_states=observations)
            time.sleep(.5)
        raise RuntimeError('native_off_not_confirmed')
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except Exception as error:
        # A timeout/nonzero/unknown result may already have changed power: never try the other side.
        save_receipt(path, dict(receipt, phase='uncertain', error_type=type(error).__name__))
        raise


# 【中文注释】函数 serve：加载固定映射与私有认证，启动受限TLS服务及两条SSH转发；每个请求都校验身份。
def serve(private):
    config = json.loads((private / 'broker-config.json').read_text(encoding='utf-8'))
    assert set(config['mapping']) == {'stor-svc-01', 'stor-svc-02'}
    assert set(config['callers']) == set(config['mapping'])
    assert config['read_only'] is False and config['off_policy'] == POLICY
    ssh = config['ssh']
    session = os.urandom(16).hex()
    signing_key = os.urandom(32)  # Per-process key; old capabilities fail after controller restart.

    # 【中文注释】函数 log：记录本轮事件/请求关联；不写认证头、令牌或私钥正文。
    def log(event, **fields):
        with (private / 'channel-events.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps({'time_local': datetime.datetime.now().isoformat(),
                                'event': event, **fields}) + '\n')

    # 【中文注释】将该职责的请求处理/连接状态组织在此类内，具体方法的失败边界见下方。
    class Handler(http.server.BaseHTTPRequestHandler):
        # 【中文注释】函数 setup：初始化连接读写对象和本版本的读入期限。
        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        # 【中文注释】函数 log_message：处理HTTP访问日志；本版本可能禁用它，以避免记录敏感请求头。
        def log_message(self, *args):
            pass  # Never retain request headers or authentication material.

        # 【中文注释】函数 reply：返回结构化JSON与HTTP状态；失败必须与可验证的成功区分。
        def reply(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)

        # 【中文注释】函数 do_GET：处理GET分支；当前控制协议要求POST，普通GET不能触发电源操作。
        def do_GET(self):
            self.reply(405, {'error': 'post_required'})

        # 【中文注释】函数 do_POST：验证认证/正文/目标/动作，取得串行锁后执行；异常返回失败而非伪造off。
        def do_POST(self):
            caller = self.headers.get('X-Storage-Caller', '')
            auth = self.headers.get('Authorization', '')
            wanted = config['callers'].get(caller)
            if not wanted or not hmac.compare_digest(auth, 'Bearer ' + wanted):
                self.reply(401, {'error': 'authentication_failed'})
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 1 <= length <= 1024:
                    raise ValueError('body_size_denied')
                value = json.loads(self.rfile.read(length))
                if not isinstance(value, dict):
                    raise ValueError('schema_denied')
                expected = {'action', 'node', 'nonce', 'permit'} if value.get('action') == 'off' else {'action', 'node', 'nonce'}
                if set(value) != expected:
                    raise ValueError('schema_denied')
                if not re.fullmatch('[0-9a-f]{32}', str(value['nonce'])):
                    raise ValueError('nonce_denied')
                if self.path != '/v1/power' or value['action'] not in ('status','prepare_off','off'):
                    raise ValueError('action_denied')
                if value['node'] not in config['mapping']:
                    raise ValueError('target_denied')
                if not LOCK.acquire(timeout=20):
                    raise RuntimeError('controller_busy')
                try:
                    if value['action']=='status':
                        body = status(value['node'], config['mapping'])
                    elif value['action']=='prepare_off':
                        body = prepare_off(caller,value['node'],value['nonce'],config['mapping'],
                                           private,session,signing_key)
                    else:
                        log('off_request_received',caller=caller,node=value['node'],request_id=value['nonce'])
                        try:
                            body = automatic_off(caller,value['node'],value['nonce'],value['permit'],
                                                 config['mapping'],private,session,signing_key)
                        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
                        except Exception:
                            log('off_failed',caller=caller,node=value['node'],request_id=value['nonce'])
                            raise
                        log('off_confirmed',caller=caller,node=value['node'],request_id=value['nonce'],power_state=body['power_state'])
                # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
                finally:
                    LOCK.release()
                self.reply(200, dict(body, nonce=value['nonce'], read_only=False,off_policy=POLICY))
            # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
            except ValueError as error:
                self.reply(400, {'error': str(error)})
            # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
            except Exception as error:
                log('request_failed', error_type=type(error).__name__)
                self.reply(503, {'error': 'power_state_unavailable'})

    # 【中文注释】将该职责的请求处理/连接状态组织在此类内，具体方法的失败边界见下方。
    class ExclusiveServer(http.server.ThreadingHTTPServer):
        allow_reuse_address = False

        # 【中文注释】函数 server_bind：启用Windows独占监听，防止重复控制器共享端口。
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

        # 【中文注释】函数 get_request：对TLS握手设置期限，防止静默连接一直占住接入。
        def get_request(self):
            connection, address = self.socket.accept()
            try:
                connection.settimeout(10)
                return context.wrap_socket(connection, server_side=True), address
            # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
            except Exception:
                connection.close()
                raise

    server = ExclusiveServer(('127.0.0.1', 8767), Handler)
    server.timeout = 1
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(private / 'channel-cert.pem', private / 'channel-key.pem')
    # Handshake has a bounded timeout; a silent socket cannot hold accept forever.

    # ponytail: one host serializes this two-VM lab; a real HA platform replaces it.
    # 【中文注释】函数 tunnel：维护专属loopback反向SSH；断开后重建，不能把隧道进程存在当作查询成功。
    def tunnel(caller, host):
        while True:
            # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
            p = subprocess.Popen(ssh + ['-N', '-T', '-o', 'ExitOnForwardFailure=yes',
                '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                '-R', '127.0.0.1:9447:127.0.0.1:8767', host],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            log('tunnel_process_started', caller=caller, pid=p.pid)
            log('tunnel_process_exited', caller=caller, returncode=p.wait())
            time.sleep(10)

    # 【中文注释】保存本轮文件/证据；沿用原存在性检查，不覆盖历史事实。
    (private / 'broker.pid').write_text(str(os.getpid()), encoding='ascii')
    # 【中文注释】保存本轮文件/证据；沿用原存在性检查，不覆盖历史事实。
    (private / 'session.json').write_text(json.dumps({'pid':os.getpid(),'session_id':session}),encoding='utf-8')
    log('controller_started', pid=os.getpid(), off_policy=POLICY)
    for caller, host in [('stor-svc-01', 'lab-stor-01'), ('stor-svc-02', 'lab-stor-02')]:
        threading.Thread(target=tunnel, args=(caller, host), daemon=True).start()
    server.serve_forever()


# 【中文注释】函数 self_check：执行源码规定的自检路径；假后端/隔离样本不能当作真实现场故障通过。
def self_check():
    for state in STATES:
        assert parse_power(0, 'PowerState: ' + state + '\ncleanShutdown: false\n') == state
    for rc, body in [(1, 'PowerState: off'), (0, ''), (0, 'Error: absent'),
                     (0, 'PowerState: on\nPowerState: off'), (0, 'PowerState: unknown'),
                     (0, 'Total running VMs: 0')]:
        try:
            parse_power(rc, body)
        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
        except RuntimeError:
            pass
        else:
            raise AssertionError('Unknown/error became successful power state')
    try:
        status('client-linux-01', {})
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except ValueError:
        pass
    else:
        raise AssertionError('Unlisted target allowed')
    print('BROKER_READONLY_SELF_CHECK=pass')


# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['--self-check']:
        self_check()
    else:
        assert len(sys.argv) == 2
        serve(Path(sys.argv[1]))
