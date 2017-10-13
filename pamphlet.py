from _pamphlet import lib, ffi
import collections
import six
import threading

__all__ = ['PamApplication', 'ThreadedPamApplication']

# Import the PAM_* constants from the cffi library
g = globals()
for key in dir(lib):
    if key.isupper():
        g[key] = getattr(lib, key)

def encode(data):
    if isinstance(data, six.binary_type):
        return data
    if not isinstance(data, six.text_type):
        raise ValueError("Only strings and bytes accepted")
    return data.encode('utf-8')

def decode(data):
    if data == ffi.NULL:
        return None
    if isinstance(data, ffi.CData):
        data = ffi.string(data)
    if isinstance(data, six.text_type):
        return data
    return data.decode('utf-8')

def pamitem(item_type):
    def getter(self):
        item = ffi.new('void **')
        self.last_status = lib.pam_get_item(self.pam_handle[0], item_type, item)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Failed to get pam item", self.pam_handle[0], self.last_status)
        return decode(ffi.cast('char *', item[0]))
    
    def setter(self, value):
        self.last_status = lib.pam_set_item(self.pam_handle[0], item_type, encode(value))
        if self.last_status != PAM_SUCCESS:
            raise PamError("Failed to set pam item", self.pam_handle[0], self.last_status)

    return property(getter, setter)

class PamApplication(object):
    def __init__(self, service_name, user_name=None):
        self.service_name = encode(service_name)
        self.user_name = encode(user_name) if user_name else ffi.NULL
        self.pam_handle = None
        self.has_credentials = False
        self.has_session = False
        self.environ = {}

        self.handle = ffi.new_handle(self)
        self.pam_conv = ffi.new('struct pam_conv *')
        self.pam_conv.conv = lib.conversation
        self.pam_conv.appdata_ptr = self.handle

        self.pam_handle = ffi.new('pam_handle_t **')

        self.last_status = lib.pam_start(self.service_name, self.user_name, self.pam_conv, self.pam_handle);
        if self.last_status != PAM_SUCCESS:
            raise PamError("pam_start failed", self.pam_handle[0], self.last_status)

        self.environ = PamEnvironment(self.pam_handle[0])

    def authenticate(self, silent=False, disallow_null_authtoken=False):
        flags = 0
        if silent:
            flags |= PAM_SILENT
        if disallow_null_authtoken:
            flags |= PAM_DISALLOW_NULL_AUTHTOK
        self.last_status = lib.pam_authenticate(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Authentication failed", self.pam_handle[0], self.last_status)

    def account_management(self, silent=False, disallow_null_authtoken=False):
        flags = 0
        if silent:
            flags |= PAM_SILENT
        if disallow_null_authtoken:
            flags |= PAM_DISALLOW_NULL_AUTHTOK
        self.last_status = lib.pam_acct_mgmt(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Account management failed", self.pam_handle[0], self.last_status)

    def open_session(self, silent=False):
        flags = PAM_SILENT if silent else 0
        self.last_status = lib.pam_open_session(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Opening session failed", self.pam_handle[0], self.last_status)
        self.has_session = True

    def close_session(self, silent=False):
        flags = PAM_SILENT if silent else 0
        self.last_status = lib.pam_close_session(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Closing session failed", self.pam_handle[0], self.last_status)
        self.has_session = False

    def get_user(self, prompt=None):
        user = ffi.new('char **')
        self.last_status = lib.pam_get_user(self.pam_handle[0], user, encode(prompt) if prompt else ffi.NULL)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Failed to get user", self.pam_handle[0], self.last_status)
        return decode(user[0])

    def change_authtoken(self, silent=False, change_expired_authtoken=False):
        flags = 0
        if silent:
            flags |= PAM_SILENT
        if change_expired_authtoken:
            flags |= PAM_CHANGE_EXPIRED_AUTHTOK
        self.last_status = lib.pam_chauthtok(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Failed to change authtoken", self.pam_handle[0], self.last_status)


    def initialize_credentials(self, silent=False):
        flags = PAM_ESTABLISH_CRED | PAM_SILENT if silent else PAM_ESTABLISH_CRED
        self.last_status = lib.pam_setcred(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Failed to initialize credentials", self.pam_handle[0], self.last_status)
        self.has_credentials = True

    def delete_credentials(self, silent=False):
        flags = PAM_DELETE_CRED | PAM_SILENT if silent else PAM_DELETE_CRED
        self.last_status = lib.pam_setcred(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            raise PamError("Failed to delete credentials", self.pam_handle[0], self.last_status)
        self.has_credentials = False

    def reinitialize_credentials(self, silent=False):
        flags = PAM_REINITIALIZE_CRED | PAM_SILENT if silent else PAM_REINITIALIZECRED
        self.last_status = lib.pam_setcred(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            self.has_credentials = False
            raise PamError("Failed to reinitialize credentials", self.pam_handle[0], self.last_status)

    def refresh_credentials(self, silent=False):
        flags = PAM_REFRESH_CRED | PAM_SILENT if silent else PAM_REFRESH_CRED
        self.last_status = lib.pam_setcred(self.pam_handle[0], flags)
        if self.last_status != PAM_SUCCESS:
            self.has_credentials = False
            raise PamError("Failed to refresh credentials", self.pam_handle[0], self.last_status)

    def end(self):
        if self.has_credentials:
            self.delete_credentials()
        if self.has_session:
            self.close_session()
        if self.pam_handle:
            ret = lib.pam_end(self.pam_handle[0], self.last_status)
            if ret != PAM_SUCCESS:
                raise PamError("pam_end failed", self.pam_handle[0], ret)
            del self.pam_handle
            del self.pam_conv
            self.pam_handle = None

    authtok_type = pamitem(PAM_AUTHTOK_TYPE)
    rhost = pamitem(PAM_RHOST)
    ruser = pamitem(PAM_RUSER)
    service = pamitem(PAM_SERVICE)
    tty = pamitem(PAM_TTY)
    user = pamitem(PAM_USER)
    user_prompt = pamitem(PAM_USER_PROMPT)
    xdisplay = pamitem(PAM_XDISPLAY)

    def __del__(self):
        if hasattr(self, 'pam_session'):
            self.end()

    def conversation(self, messages):
        raise RuntimeError("This method must be overridden")

class PamEnvironment(collections.MutableMapping):
    def __init__(self, handle):
        self.handle = handle

    def __getitem__(self, key):
        ret = lib.pam_getenv(self.handle, encode(key))
        if ret == ffi.NULL:
            raise KeyError(key)
        return decode(ret)

    def __setitem__(self, key, value):
        ret = lib.pam_putenv(self.handle, encode('=').join([encode(key), encode(value)]))
        if ret != PAM_SUCCESS:
            raise PamError("Failed to set pam environment", self.handle[0], ret)

    def __delitem__(self, key):
        ret = lib.pam_putenv(self.handle, encode(key))
        if ret == PAM_BAD_ITEM:
            raise KeyError(key)
        elif ret != PAM_SUCCESS:
            raise PamError("Failed to set pam environment", self.handle[0], ret)

    def __iter__(self):
        i = 0
        env = lib.pam_getenvlist(self.handle)
        while env[i]:
            kv = decode(env[i])
            yield kv[:kv.find('=')]
            i += 1
        lib.free(env)

    def __len__(self):
        return len(self[:])

    def __repr__(self):
        return '{' + ', '.join(['%s: %s' % (repr(x), repr(self[x])) for x in self]) + '}'

class ConversationThread(threading.Thread):
    def __init__(self, obj, method, *args):
        super(ConversationThread, self).__init__()
        self.obj = obj
        self.method = method
        self.args = args

    def run(self):
        try:
            self.obj.set_data(self.method(*self.args))
        except Exception as e:
            self.obj.set_data(e)

class ThreadedPamApplication(PamApplication):
    def __init__(self, service_name, user_name=None, timeout=60):
        super(ThreadedPamApplication, self).__init__(service_name, user_name)
        self.data = self.input = None
        self.has_data = threading.Event()
        self.has_input = threading.Event()
        self.timeout = timeout

    def authenticate(self, silent=False, disallow_null_authtoken=False):
        t = ConversationThread(self, super(ThreadedPamApplication, self).authenticate, silent, disallow_null_authtoken)
        t.start()
        return t

    def change_authtoken(self, silent=False, change_expired_authtoken=False):
        t = ConversationThread(self, super(ThreadedPamApplication, self).change_authtoken, silent, change_expired_authtoken)
        t.start()
        return t

    def conversation(self, messages):
        self.set_data(messages)
        answers = self.get_input()
        if not answers:
            return [''] * len(messages)
        return answers

    def set_data(self, data):
        self.data = data
        self.has_data.set()

    def get_data(self):
        self.has_data.wait(self.timeout)
        self.has_data.clear()
        data, self.data = self.data, None
        return data

    def set_input(self, answers):
        self.input = answers
        self.has_input.set()

    def get_input(self):
        self.has_input.wait(self.timeout)
        self.has_input.clear()
        input, self.input = self.input, None
        return input

leaky_allocator = ffi.new_allocator(alloc=lib.malloc, free=None)
@ffi.def_extern()
def conversation(num_msg, msg, resp, appdata_ptr):
    pam = ffi.from_handle(appdata_ptr)
    messages = [PamMessage.from_wire(msg[x]) for x in range(num_msg)]
    responses = list(pam.conversation(messages))
    assert len(responses) == len(messages)
    # The pam modules clear/free this array, hence the leaky allocation
    resp[0] = leaky_allocator('struct pam_response[]', len(responses))
    for (i, text) in enumerate(responses):
        resp[0][i].resp_retcode = 0
        resp[0][i].resp = lib.strdup(encode(text))
    return PAM_SUCCESS

class PamMessage(str):
    def __new__(self, message, style):
        return super(PamMessage, self).__new__(self, message)

    def __init__(self, message, style):
        self.style = style
        self.message = message

    @property
    def style_text(self):
        return {
            PAM_PROMPT_ECHO_ON: 'prompt',
            PAM_PROMPT_ECHO_OFF: 'password prompt',
            PAM_TEXT_INFO: 'message',
            PAM_ERROR_MSG: 'error'
        }[self.style]

    is_prompt = property(lambda self: self.style in (PAM_PROMPT_ECHO_ON, PAM_PROMPT_ECHO_OFF))
    wants_password = property(lambda self: self.style == PAM_PROMPT_ECHO_OFF)
    is_error = property(lambda self: self.style == PAM_ERROR_MSG)

    @classmethod
    def from_wire(klass, data):
        return PamMessage(decode(data.msg), data.msg_style)

    def __repr__(self):
        return '<PamMessage "%s" (%s)>' % (self.message, self.style_text)

# One of my favourite python metaprogramming tricks: auto-specializing
# classes.Simply raise a PamError and you automatically get the correct
# subclass.
class PamErrorMeta(type):
    def __new__(cls, name, parents, attrs):
        __all__.append(name)
        klass = super(PamErrorMeta, cls).__new__(cls, name, parents, attrs)
        if name == 'PamError':
            klass.subclasses = {}
        else:
            PamError.subclasses[klass.code] = klass
        return klass

@six.add_metaclass(PamErrorMeta)
class PamError(Exception):
    def __new__(klass, msg, handle=None, code=None):
        if klass == PamError and code in klass.subclasses:
            return klass.subclasses[code](msg, handle, code)
        return super(PamError, klass).__new__(klass, msg, handle, code)

    def __init__(self, msg, handle=None, code=None):
        if handle and code:
            msg += ': ' + decode(lib.pam_strerror(handle, code))
        if code:
            self.code = code

        super(PamError, self).__init__(msg)

class Abort(PamError):                      code = PAM_ABORT
class AccountExpired(PamError):             code = PAM_ACCT_EXPIRED
class AuthenticationError(PamError):        code = PAM_AUTH_ERR
class AuthinfoUnavailable(PamError):        code = PAM_AUTHINFO_UNAVAIL
class AuthTokenAgingDisabled(PamError):     code = PAM_AUTHTOK_DISABLE_AGING
class AuthTokenManipulationError(PamError): code = PAM_AUTHTOK_ERR
class AuthTokenExpired(PamError):           code = PAM_AUTHTOK_EXPIRED
class AuthTokenLockBusy(PamError):          code = PAM_AUTHTOK_LOCK_BUSY
class AuthTokenRecoveryError(PamError):     code = PAM_AUTHTOK_RECOVERY_ERR
class BadItem(PamError):                    code = PAM_BAD_ITEM
class BufferError(PamError):                code = PAM_BUF_ERR
class ConversationError(PamError):          code = PAM_CONV_ERR
class CredentialError(PamError):            code = PAM_CRED_ERR
class CredentialExpired(PamError):          code = PAM_CRED_EXPIRED
class InsufficientCredentials(PamError):    code = PAM_CRED_INSUFFICIENT
class CredentialsUnavailable(PamError):     code = PAM_CRED_UNAVAIL
class MaxTriesExceeded(PamError):           code = PAM_MAXTRIES
class NewAuthTokenRequired(PamError):       code = PAM_NEW_AUTHTOK_REQD
class PermissionDenied(PamError):           code = PAM_PERM_DENIED
class ServiceError(PamError):               code = PAM_SERVICE_ERR
class SessionError(PamError):               code = PAM_SESSION_ERR
class SymbolError(PamError):                code = PAM_SYMBOL_ERR
class SystemError(PamError):                code = PAM_SYSTEM_ERR
class UserUnknown(PamError):                code = PAM_USER_UNKNOWN

if __name__ == '__main__':
    import getpass
    import sys, os
    class Example(PamApplication):
        def conversation(self, messages):
            for message in messages:
                if not message.is_prompt:
                    print(message)
                    yield ""
                elif message.wants_password:
                    yield getpass.getpass(message.rstrip() + ' ')
                else:
                    yield six.moves.input(message.rstrip() + ' ')

    app = Example('pamphlet')
    app.tty = os.ttyname(sys.stdin.fileno())
    if 'DISPLAY' in os.environ:
        app.xdisplay = os.environ['DISPLAY']
    app.authenticate()
    app.initialize_credentials()
    app.account_management()
    app.open_session()
    # app.change_authtoken()
    app.close_session()
    app.end()
