Writing pam applications with ease using pamphlet
=================================================

pamphlet allows you to authenticate your users using pam without needing to
jump through hoops. All you do is subclass `pamphlet.PamApplication` and
provide a `conversation` function.

Of course you can do more, the full power of pam lies at your fingertips!

Let's start with the simplest example possible:

```python
import pamphlet

class MyApp(pamphlet.PamAplication):
    def conversation(self, messages):
        for message in messages:
            if not message.is_prompt:
                print(message)
                yield ""
            elif message.wants_password:
                yield getpass.getpass(message.rstrip() + ' ')
            else:
                yield six.moves.input(message.rstrip() + ' ')

app = MyApp('pamphlet-example')
app.authenticate()
```

This application simply prints all messages and asks the user whatever pam
wants to know. Usually this will be a loginname and password, but it could just
as easily be a 2fa token or any other thing you configure your pam stack to do.

The conversation function
-------------------------
The pam stack and user communicate with messages. How these messages are
displayed is up to you; the conversation function can do pretty much anything
it wants.

The conversation function will be passed a single argument: a list of messages.
These messages are strings with a few extra attributes:

*  `style`. The style of the message, one of `PAM_TEXT_INFO`, `PAM_ERROR_MSG`,
   `PAM_PROMPT_ECHO_ON` and `PAM_PROMPT_ECHO_OFF`. This indicates the type of
   message, but doesn't need to be used directly. Instead, you can use the
   following attributes.
* `is_prompt` indicates whether the message is a question or not
* `is_error` indicates whether the message is an error message
* `wants_password` indicates whether the message expects a secret

The return value for this function must be a list of strings, containing an
answer for each message. Messages that are not prompts must be answered too,
the answer should be an empty string.

Pam phases
----------
A well-behaved pam application does not only call `authenticate()` but also the
other phases of the pam stack. A more complete example would be

```python
app = MyApp('pamphlet-example')
app.authenticate()
app.initialize_credentials()
app.account_management()
app.open_session()
... # Here actual work happens
app.end()
```

Changing passwords
------------------
Pam can also be used to change authentication tokens such as passwords, which
of course can be done with pamphlet as well.

```python
app = MyApp('pamphlet-example')
app.authenticate()
app.change_authtoken()
```

Like `authenticate`, `change_authtoken` will use the conversation function to
interact wit the user, e.g. to ask for a new password.

Credentials
-----------

The pam environment
-------------------
The pam stack keeps its own 'environment', which, like `os.environ`, has been
made accessible as a dict-like object. This object can be found as the
`environ` attribute of `PamApplication` instances.

Pam items
---------
To help the pam stack make decisions about users, several data items can be set
and retrieved by pam modules and applications. `PamApplication` objects have
several properties that provide access to these items:

* `authtok_type` - The type of authentication token (the "UNIX" in "New UNIX password")
* `rhost` - Host the user is connecting from 
* `ruser` - Requesting user, may very well be NULL
* `service` - The PAM service in use, which determines which modules to access
* `tty` - The tty the user is using
* `user` - The username of the authenticating user. Note that this may be
  mapped to another username by any pam function, so don't cache this beyond
  calls to any pam function
* `user_prompt` - The string to use to ask the user for their loginname, e.g. 'login: '
* `xdisplay` - The X display the user is using, if any.

To illustrate, here is an example of a local commandline program that sets the
tty name and the X display:

```python
app = Example('pamphlet')
app.tty = os.ttyname(sys.stdin.fileno())
if 'DISPLAY' in os.environ:
    app.xdisplay = os.environ['DISPLAY']
app.authenticate()
app.initialize_credentials()
app.acct_mgmt()
app.open_session()
app.change_authtoken()
app.close_session()
app.end()
```

Full API
--------

`app = pamphlet.PamApplication(service_name, user_name=None)`

Creating a PamApplication object creates a pam handle and initializes a pam
stack. When you're done with the pam handle, you can call `app.end()` to
release resources.

`app.end()`

When you're done with the pam handle, so after the user's session has ended,
you need to call the `end` function. This will delete any established
credentials, close any open sessions and invalidate the pam handle. The app
object should not be used afterward.

`app.authenticate(silent=False, disallow_null_authtoken=False)`

Authenticates the user. This may cause the conversation function to be called
to ask the user for input.

`app.account_management(silent=False, disallow_null_authtoken=False)`

Called after authenticating to check the user's account. This can for example
reject users whose account has expired.

`app.open_session(silent=False)`<br />
`app.close_session(silent=False)`
Opens and closes user sessions. This could perform tasks like creating the
users homedir.

`app.change_authtoken(silent=False, change_expired_authtoken=False)`
Change the user's password or other authentication token.

`app.initialize_credentials(silent=False)`<br />
`app.delete_credentials(silent=False)`<br />
`app.reinitialize_credentials(silent=False)`<br />
`app.refresh_credentials(silent=False)`

Manage a users credentials (such as kerberos tickets). Note that uid, gid and
supplementary groups are not managed by this and should be set with
`os.initgroups`.

`app.get_user(self, prompt=None):`

Get the loginname of the user. This is mostley meant for pam modules, but can
be used by applications. It may prompt the user for their username using the
conversation function. Generally, you'll want to read the `user` item instead
of using this function.

`app.authtok_type`<br />
`app.rhost`<br />
`app.ruser`<br />
`app.service`<br />
`app.tty`<br />
`app.user`<br />
`app.user_prompt`<br />
`app.xdisplay`

These properties correspond to pam items.

Exceptions
----------
Whereas the C level pam functions return either `PAM_SUCCESS` or an error code,
the methods of the `PamApplication` object return nothing. Errors are signaled
in a more pythonic way using exceptions. Each pam error code is a separate
exception, but all exceptions are subclasses of PamError.

Here is the full list of exceptions and the pam return code each of the
exceptions corresponds to.

```python
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
class CredenrialsUnavailable(PamError):     code = PAM_CRED_UNAVAIL
class MaxTriesExceeded(PamError):           code = PAM_MAXTRIES
class NewAuthTokenRequired(PamError):       code = PAM_NEW_AUTHTOK_REQD
class PermissionDenied(PamError):           code = PAM_PERM_DENIED
class ServiceError(PamError):               code = PAM_SERVICE_ERR
class SessionError(PamError):               code = PAM_SESSION_ERR
class SymbolError(PamError):                code = PAM_SYMBOL_ERR
class SystemError(PamError):                code = PAM_SYSTEM_ERR
class UserUnknown(PamError):                code = PAM_USER_UNKNOWN
```

Threaded pam application
------------------------
One downside of the pam model of interacting is that a call to functions like
`authenticate` may be blocking when they require input. They also require you
to be able to ask the user questions and return their responses.

There are scenarios where this is not possible, for example when using event
driven I/O. Proper integration with event loops is still on the roadmap for
pamphlet, but you can get a long way with the ThreadedPamApplication subclass.

An example of this (and really, the reason why pamphlet was written) is an ssh
server written using paramiko. In its model, you cannot ask the user questions.
You can submit questions, and the answers will be handed to you later in a
separate callback.

Given that paramiko uses threads extensively, a pam thread makes sense here as
well. The code looks like this (full example is included in the source):

```python
class SshAuthInterface(paramiko.server.ServerInterface):
    def __init__(self, pam_service):
        self.pam_service = pam_service
        self.logger = logging.getLogger("ssh.auth")

    def get_allowed_auths(self, username):
        return "keyboard-interactive"

    def check_auth_interactive(self, username, submethods):
        self.pam = pamphlet.ThreadedPamApplication(self.pam_service, username)
        self.auth_thread = self.pam.authenticate()
        data = self.pam.get_data()
        if isinstance(data, Exception):
            self.logger.exception(data)
            self.auth_thread.join()
            return paramiko.AUTH_FAILED
        if not data:
            return paramiko.AUTH_FAILED
        q = paramiko.server.InteractiveQuery()
        for prompt in data:
            q.add_prompt(prompt, not prompt.wants_password)
        return q

    def check_auth_interactive_response(self, responses):
        self.pam.set_input(responses)
        data = self.pam.get_data()
        if isinstance(data, Exception):
            self.logger.exception(data)
            self.auth_thread.join()
            return paramiko.AUTH_FAILED
        if not data:
            self.auth_thread.join()
            return paramiko.AUTH_SUCCESSFUL
        q = paramiko.server.InteractiveQuery()
        for prompt in data:
            q.add_prompt(prompt, not prompt.wants_password)
        return q
```

Instead of subclassing `ThreadedPamApplication` and providing a conversation
function, you simply instantiate the class. The `authenticate` and
`change_authtoken` functions return a thread, which you need to join once the
conversation is complete.

To get data from the pam stack, call `app.get_data()`. This returns either a
list of prompts to answer, an exception that occurred or `None` to indicate
succesful completion of the `authenticate` or `change_authtoken` function.

To feed answers back into the pam stack, call `app.set_input()`. The argument
should be a list of answers, same as what you would return from a conversation
function.
