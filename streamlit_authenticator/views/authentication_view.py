"""
Script description: This module renders the login, logout, register user, reset password,
forgot password, forgot username, and modify user details widgets.

Libraries imported:
-------------------
- json: Handles JSON documents.
- time: Implements sleep function.
- typing: Implements standard typing notations for Python functions.
- streamlit: Framework used to build pure Python web applications.
"""

import json
import time
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

import streamlit as st
from streamlit_extras.stylable_container import stylable_container

from ..controllers import AuthenticationController, CookieController
from .. import params
from ..utilities import (DeprecationError,
                         Encryptor,
                         Helpers,
                         LogoutError,
                         ResetError,
                         UpdateError,
                         Validator)


class Authenticate:
    """
    This class renders login, logout, register user, reset password, forgot password,
    forgot username, and modify user details widgets.
    """
    def __init__(
            self,
            credentials: Union[Dict[str, Any], str],
            cookie_name: str = 'some_cookie_name',
            cookie_key: str = 'some_key',
            cookie_expiry_days: float = 30.0,
            validator: Optional[Validator] = None,
            auto_hash: bool = True,
            api_key: Optional[str] = None,
            **kwargs: Optional[Dict[str, Any]]
            ) -> None:
        """
        Initializes an instance of Authenticate.

        Parameters
        ----------
        credentials : dict or str
            Dictionary of user credentials or path to a configuration file.
        cookie_name : str, default='some_cookie_name'
            Name of the re-authentication cookie stored in the client's browser.
        cookie_key : str, default='some_key'
            Secret key used for encrypting the re-authentication cookie.
        cookie_expiry_days : float, default=30.0
            Expiry time for the re-authentication cookie in days.
        validator : Validator, optional
            Validator object for checking username, name, and email validity.
        auto_hash : bool, default=True
            If True, passwords will be automatically hashed.
        api_key : str, optional
            API key for sending password reset and authentication emails.
        **kwargs : dict, optional
            Additional keyword arguments.
        """
        self.api_key = api_key
        self.attrs = kwargs
        self.secret_key = cookie_key
        if isinstance(validator, dict):
            raise DeprecationError(f"""Please note that the 'pre_authorized' parameter has been
                                   removed from the Authenticate class and added directly to the
                                   'register_user' function. For further information please refer to
                                   {params.REGISTER_USER_LINK}.""")
        self.path = credentials if isinstance(credentials, str) else None
        self.cookie_controller          =   CookieController(cookie_name,
                                                             cookie_key,
                                                             cookie_expiry_days,
                                                             self.path)
        self.authentication_controller  =   AuthenticationController(credentials,
                                                                     validator,
                                                                     auto_hash,
                                                                     self.path,
                                                                     self.api_key,
                                                                     self.secret_key,
                                                                     self.attrs.get('server_url'))
        self.encryptor = Encryptor(self.secret_key)

    # Forgot password
    def forgot_password(
        self, location: Literal['main', 'sidebar'] = 'main',
        fields: Optional[Dict[str, str]] = None, captcha: bool = False,
        send_email: bool = False, two_factor_auth: bool = False,
        clear_on_submit: bool = False, key: str = 'Forgot password',
        callback: Optional[Callable] = None, container_css: Optional[str] = None,
        use_cols: bool = True
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Renders a forgot password widget.

        Parameters
        ----------
        location : {'main', 'sidebar'}, default='main'
            Location of the forgot password widget.
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=False
            If True, requires captcha validation.
        send_email : bool, default=False
            If True, sends the new password to the user's email.
        two_factor_auth : bool, default=False
            If True, enables two-factor authentication.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Forgot password'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to be executed after form submission.
        container_css : str, optional
            CSS styles to be applied to the container.
        use_cols : bool, default=True
            If True, uses columns for buttons.

        Returns
        -------
        tuple[str, str, str] or (None, None, None)
            - Username associated with the forgotten password.
            - Email associated with the forgotten password.
            - New plain-text password to be securely transferred to the user.
        """
        if fields is None:
            fields = {'Form name':'Forgot password', 'Username':'Username', 'Captcha':'Captcha',
                      'Submit':'Submit', 'Dialog name':'Verification code', 'Code':'Code',
                      'Error':'Code is incorrect'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not container_css:
            container_css = """
                {
                    border-radius: 1rem;
                    border: 2px solid #49485611;
                    box-shadow: 1px 1px 3px #49485621;
                    padding: 1em 1.5em;
                }
            """
        with stylable_container(
            key="forgot_password_container",
            css_styles=container_css,
        ):
            if location == 'main':
                forgot_password_form = st.form(
                    key=key, clear_on_submit=clear_on_submit, border=False
                )
            else:
                forgot_password_form = st.sidebar.form(
                    key=key, clear_on_submit=clear_on_submit, border=False
                )
        forgot_password_form.markdown(
            f"<h4 style='text-align: center;'>{fields.get('Form name', 'Forgot password')}</h4>",
            unsafe_allow_html=True
        )
        username = forgot_password_form.text_input(
            fields.get('Username', 'Username'), autocomplete='off'
        )
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_password_form.text_input(
                fields.get('Captcha', 'Captcha'), autocomplete='off'
            )
            forgot_password_form.image(
                Helpers.generate_captcha('forgot_password_captcha', self.secret_key)
            )
        result = (None, None, None)
        if use_cols:
            cols = forgot_password_form.columns([1, 1.5, 1], gap="medium")[1]
        else:
            cols = forgot_password_form
        submit = cols.form_submit_button(
            fields.get('Submit', 'Request a new password'),
            use_container_width=True, icon=":material/send:", type="primary"
        )
        forgot_password_form.write("")
        if submit:
            result = self.authentication_controller.forgot_password(
                username, callback, captcha, entered_captcha
            )
            if not two_factor_auth:
                if send_email:
                    self.authentication_controller.send_password(result)
                return result
            self.__two_factor_auth(result[1], result, widget='forgot_password', fields=fields)
        if two_factor_auth and st.session_state.get('2FA_check_forgot_password'):
            decrypted = self.encryptor.decrypt(st.session_state['2FA_content_forgot_password'])
            result = json.loads(decrypted)
            if send_email:
                self.authentication_controller.send_password(result)
            del st.session_state['2FA_check_forgot_password']
            return result
        return None, None, None

    # Forgot username
    def forgot_username(
        self, location: Literal['main', 'sidebar'] = 'main',
        fields: Optional[Dict[str, str]] = None, captcha: bool = False,
        send_email: bool = False, two_factor_auth: bool = False,
        clear_on_submit: bool = False, key: str = 'Forgot username',
        callback: Optional[Callable]=None, container_css: Optional[str] = None,
        use_cols: bool = True
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Renders a forgot username widget.

        Parameters
        ----------
        location : {'main', 'sidebar'}, default='main'
            Location of the forgot username widget.
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=False
            If True, requires captcha validation.
        send_email : bool, default=False
            If True, sends the retrieved username to the user's email.
        two_factor_auth : bool, default=False
            If True, enables two-factor authentication.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Forgot username'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to be executed after form submission.
        container_css : str, optional
            CSS styles to be applied to the container.
        use_cols : bool, default=True
            If True, uses columns for buttons.

        Returns
        -------
        tuple[str, str] or (None, str)
            - Username associated with the forgotten username.
            - Email associated with the forgotten username.
        """
        if fields is None:
            fields = {'Form name':'Forgot username', 'Email':'Email', 'Captcha':'Captcha',
                      'Submit':'Submit', 'Dialog name':'Verification code', 'Code':'Code',
                      'Error':'Code is incorrect'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not container_css:
            # using background image centered
            container_css = """
                {
                    border-radius: 1rem;
                    border: 2px solid #49485611;
                    box-shadow: 1px 1px 3px #49485621;
                    padding: 1em 1.5em;
                }
            """
        with stylable_container(
            key="forgot_user_container",
            css_styles=container_css,
        ):
            if location == 'main':
                forgot_username_form = st.form(
                    key=key, clear_on_submit=clear_on_submit, border=False
                )
            else:
                forgot_username_form = st.sidebar.form(
                    key=key, clear_on_submit=clear_on_submit, border=False
                )
        forgot_username_form.markdown(
            f"<h4 style='text-align: center;'>{fields.get('Form name', 'Forgot username')}</h4>",
            unsafe_allow_html=True
        )
        email = forgot_username_form.text_input(
            fields.get("Email", "Email"), autocomplete='off'
        )
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_username_form.text_input(
                fields.get("Captcha", "Captcha"), autocomplete='off'
            )
            forgot_username_form.image(
                Helpers.generate_captcha('forgot_username_captcha', self.secret_key)
            )
        if use_cols:
            cols = forgot_username_form.columns([1, 1.5, 1], gap="medium")[1]
        else:
            cols = forgot_username_form
        submit = cols.form_submit_button(
            fields.get('Submit', 'Request username'),
            use_container_width=True, icon=":material/send:", type="primary"
        )
        forgot_username_form.write("")
        if submit:
            result = self.authentication_controller.forgot_username(
                email, callback, captcha, entered_captcha
            )
            if not two_factor_auth:
                if send_email:
                    self.authentication_controller.send_username(result)
                return result
            self.__two_factor_auth(email, result, widget='forgot_username', fields=fields)
        if two_factor_auth and st.session_state.get('2FA_check_forgot_username'):
            decrypted = self.encryptor.decrypt(st.session_state['2FA_content_forgot_username'])
            result = json.loads(decrypted)
            if send_email:
                self.authentication_controller.send_username(result)
            del st.session_state['2FA_check_forgot_username']
            return result
        return None, email

    # Guest login
    def experimental_guest_login(self, button_name: str='Guest login',
                                 location: Literal['main', 'sidebar'] = 'main',
                                 provider: Literal['google', 'microsoft'] = 'google',
                                 oauth2: Optional[Dict[str, Any]] = None,
                                 max_concurrent_users: Optional[int]=None,
                                 single_session: bool=False, roles: Optional[List[str]]=None,
                                 use_container_width: bool=False,
                                 callback: Optional[Callable]=None) -> None:
        """
        Renders a guest login button.

        Parameters
        ----------
        button_name : str, default='Guest login'
            Display name for the guest login button.
        location : {'main', 'sidebar'}, default='main'
            Location where the guest login button is rendered.
        provider : {'google', 'microsoft'}, default='google'
            OAuth2 provider used for authentication.
        oauth2 : dict, optional
            Configuration parameters for OAuth2 authentication.
        max_concurrent_users : int, optional
            Maximum number of users allowed to log in concurrently.
        single_session : bool, default=False
            If True, prevents users from logging into multiple sessions simultaneously.
        roles : list of str, optional
            Roles assigned to guest users.
        use_container_width : bool, default=False
            If True, the button width matches the container.
        callback : Callable, optional
            Function to execute when the button is pressed.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if provider not in ['google', 'microsoft']:
            raise ValueError("Provider must be one of 'google' or 'microsoft'")
        if not st.session_state.get('authentication_status'):
            token = self.cookie_controller.get_cookie()
            if token:
                self.authentication_controller.login(token=token)
            time.sleep(self.attrs.get('login_sleep_time', params.PRE_LOGIN_SLEEP_TIME))
            if not st.session_state.get('authentication_status'):
                auth_endpoint = \
                    self.authentication_controller.guest_login(cookie_controller=\
                                                                self.cookie_controller,
                                                                provider=provider,
                                                                oauth2=oauth2,
                                                                max_concurrent_users=\
                                                                max_concurrent_users,
                                                                single_session=single_session,
                                                                roles=roles,
                                                                callback=callback)
                if location == 'main' and auth_endpoint:
                    st.link_button(button_name, url=auth_endpoint,
                                   use_container_width=use_container_width)
                if location == 'sidebar' and auth_endpoint:
                    st.sidebar.link_button(button_name, url=auth_endpoint,
                                           use_container_width=use_container_width)

    # Login
    def login(
        self, location: Literal['main', 'sidebar', 'unrendered'] = 'main',
        max_concurrent_users: Optional[int] = None, max_login_attempts: Optional[int] = None,
        fields: Optional[Dict[str, str]] = None, captcha: bool = False,
        single_session: bool=False, clear_on_submit: bool = False, key: str = 'Login',
        callback: Optional[Callable] = None, container_css: Optional[str] = None,
        use_cols: bool = True
    ) -> Optional[Tuple[Optional[str], Optional[bool], Optional[str]]]:
        """
        Renders a login widget.

        Parameters
        ----------
        location : {'main', 'sidebar', 'unrendered'}, default='main'
            Location where the login widget is rendered.
        max_concurrent_users : int, optional
            Maximum number of users allowed to log in concurrently.
        max_login_attempts : int, optional
            Maximum number of failed login attempts allowed.
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=False
            If True, requires captcha validation.
        single_session : bool, default=False
            If True, prevents users from logging into multiple sessions simultaneously.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Login'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.
        use_cols : bool, default=True
            If True, uses columns for buttons.

        Returns
        -------
        tuple[str, bool, str] or None
            - If `location='unrendered'`, returns (user's name, authentication status, username).
            - Otherwise, returns None.
        """
        if fields is None:
            fields = {'Form name':'Login', 'Username':'Username', 'Password':'Password',
                      'Login':'Login', 'Captcha':'Captcha'}
        if not container_css:
            # using background image centered
            container_css = """
                {
                    border-radius: 1rem;
                    border: 2px solid #49485611;
                    box-shadow: 1px 1px 3px #49485621;
                    padding: 1em 1.5em;
                }
            """
        if location not in ['main', 'sidebar', 'unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if not st.session_state.get('authentication_status'):
            token = self.cookie_controller.get_cookie()
            if token:
                self.authentication_controller.login(token=token)
            time.sleep(self.attrs.get('login_sleep_time', params.PRE_LOGIN_SLEEP_TIME))
            if not st.session_state.get('authentication_status'):
                with stylable_container(
                    key="login_container",
                    css_styles=container_css,
                ):
                    if location == 'main':
                        login_form = st.form(key=key, clear_on_submit=clear_on_submit, border=False)
                    elif location == 'sidebar':
                        login_form = st.sidebar.form(
                            key=key, clear_on_submit=clear_on_submit, border=False
                        )
                    else:
                        return (
                            st.session_state['name'], st.session_state['authentication_status'],
                            st.session_state['username']
                        )
                login_form.markdown(
                    f"<h4 style='text-align: center;'>{fields.get('Form name', 'Login')}</h4>",
                    unsafe_allow_html=True
                )
                username = login_form.text_input(
                    fields.get("Username", "Username"), autocomplete='off'
                )
                if 'password_hint' in st.session_state:
                    password = login_form.text_input(
                        fields.get('Password', "Password"), type='password',
                        help=st.session_state['password_hint'],
                        autocomplete='off'
                    )
                else:
                    password = login_form.text_input(
                        fields.get("Password", "Password"), type='password', autocomplete='off'
                    )
                entered_captcha = None
                if captcha:
                    entered_captcha = login_form.text_input(
                        fields.get('Captcha', 'Captcha'), autocomplete='off'
                    )
                    login_form.image(
                        Helpers.generate_captcha('login_captcha', self.secret_key)
                    )
                if use_cols:
                    cols = login_form.columns([1, 1.5, 1], gap="medium")[1]
                else:
                    cols = login_form
                submit = cols.form_submit_button(
                    fields.get('Login', 'Login'),
                    use_container_width=True, icon=":material/login:", type="primary"
                )
                login_form.write("")
                if submit:
                    if self.authentication_controller.login(
                        username, password, max_concurrent_users,
                        max_login_attempts, single_session=single_session,
                        callback=callback, captcha=captcha,
                        entered_captcha=entered_captcha
                    ):
                        self.cookie_controller.set_cookie()
                        if self.path and self.cookie_controller.get_cookie():
                            st.rerun()

    # Logout
    def logout(
        self, button_name: str = 'Logout',
        location: Literal['main', 'sidebar', 'unrendered'] = 'main',
        key: str = 'Logout', use_container_width: bool = False,
        callback: Optional[Callable] = None
    ) -> None:
        """
        Renders a logout button.

        Parameters
        ----------
        button_name : str, default='Logout'
            Display name for the logout button.
        location : {'main', 'sidebar', 'unrendered'}, default='main'
            Location where the logout button is rendered.
        key : str, default='Logout'
            Unique key for the widget, useful in multi-page applications.
        use_container_width : bool, default=False
            If True, the button width matches the container.
        callback : Callable, optional
            Function to execute when the button is pressed.
        """
        if not st.session_state.get('authentication_status'):
            raise LogoutError('User must be logged in to use the logout button')
        if location not in ['main', 'sidebar', 'unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if location == 'main':
            if st.button(
                button_name, key=key, use_container_width=use_container_width,
                icon=":material/logout:", type="primary"
            ):
                self.authentication_controller.logout(callback)
                self.cookie_controller.delete_cookie()
        elif location == 'sidebar':
            if st.sidebar.button(
                button_name, key=key, use_container_width=use_container_width,
                icon=":material/logout:", type="primary"
            ):
                self.authentication_controller.logout(callback)
                self.cookie_controller.delete_cookie()
        elif location == 'unrendered':
            if st.session_state.get('authentication_status'):
                self.authentication_controller.logout()
                self.cookie_controller.delete_cookie()

    # Register user
    def register_user(
        self, location: Literal['main', 'sidebar'] = 'main',
        pre_authorized: Optional[List[str]] = None,
        domains: Optional[List[str]] = None, fields: Optional[Dict[str, str]] = None,
        captcha: bool = True, roles: Optional[List[str]] = None,
        merge_username_email: bool = False, password_hint: bool = True,
        two_factor_auth: bool = False, clear_on_submit: bool = False,
        key: str = 'Register user', callback: Optional[Callable] = None,
        container_css: Optional[str] = None, use_cols: bool = True,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Renders a register new user widget.

        Parameters
        ----------
        location : {'main', 'sidebar'}, default='main'
            Location where the registration widget is rendered.
        pre_authorized : list of str, optional
            List of emails of unregistered users who are authorized to register.
        domains : list of str, optional
            List of allowed email domains (e.g., ['gmail.com', 'yahoo.com']).
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=True
            If True, requires captcha validation.
        roles : list of str, optional
            User roles for registered users.
        merge_username_email : bool, default=False
            If True, uses the email as the username.
        password_hint : bool, default=True
            If True, includes a password hint field.
        two_factor_auth : bool, default=False
            If True, enables two-factor authentication.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Register user'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.
        container_css : str, optional
            CSS styles to be applied to the container.
        use_cols : bool, default=True
            If True, uses columns for buttons.

        Returns
        -------
        tuple[str, str, str] or (None, None, None)
            - Email associated with the new user.
            - Username associated with the new user.
            - Name associated with the new user.
        """
        if isinstance(pre_authorized, bool) or isinstance(pre_authorized, dict):
            raise DeprecationError(f"""Please note that the 'pre_authorized' parameter now
                                   requires a list of pre-authorized emails. For further
                                   information please refer to {params.REGISTER_USER_LINK}.""")
        if fields is None:
            fields = {'Form name':'Register user', 'First name':'First name',
                      'Last name':'Last name', 'Email':'Email', 'Username':'Username',
                      'Password':'Password', 'Repeat password':'Repeat password',
                      'Password hint':'Password hint', 'Captcha':'Captcha', 'Register':'Register',
                      'Dialog name':'Verification code', 'Code':'Code', 'Submit':'Submit',
                      'Error':'Code is incorrect'}
        if not container_css:
            container_css = """
                {
                    border-radius: 1rem;
                    border: 2px solid #49485611;
                    box-shadow: 1px 1px 3px #49485621;
                    padding: 1em 1.5em;
                }
            """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        with stylable_container(
            key="register_user_container",
            css_styles=container_css,
        ):
            if location == 'main':
                register_user_form = st.form(key=key, clear_on_submit=clear_on_submit, border=False)
            else:
                register_user_form = st.sidebar.form(
                    key=key, clear_on_submit=clear_on_submit, border=False
                )
        register_user_form.markdown(
            f"<h4 style='text-align: center;'>{fields.get('Form name', 'Register user')}</h4>",
            unsafe_allow_html=True
        )
        col1_1, col2_1 = register_user_form.columns(2)
        new_first_name = col1_1.text_input(
            fields.get("First name", "First name"), autocomplete='off'
        )
        new_last_name = col2_1.text_input(
            fields.get("Last name", "Last name"), autocomplete='off'
        )
        if merge_username_email:
            new_email = register_user_form.text_input(
                fields.get("Email", "Email"), autocomplete='off'
            )
            new_username = new_email
        else:
            new_email = col1_1.text_input(
                fields.get("Email", "Email"), autocomplete='off'
            )
            new_username = col2_1.text_input(
                fields.get("Username", "Username"), autocomplete='off'
            )
        col1_2, col2_2 = register_user_form.columns(2)
        password_instructions = self.attrs.get(
            'password_instructions', params.PASSWORD_INSTRUCTIONS
        )
        new_password = col1_2.text_input(
            fields.get("Password", "Password"), type='password',
            help=password_instructions, autocomplete='off'
        )
        new_password_repeat = col2_2.text_input(
            fields.get("Repeat password", "Repeat password"), type='password', autocomplete='off'
        )
        if password_hint:
            password_hint = register_user_form.text_input(
                fields.get("Password hint", "Password hint"), autocomplete='off'
            )
        user_roles = register_user_form.multiselect(
            fields.get("Roles", "Roles"), options=roles,
        )
        entered_captcha = None
        if captcha:
            entered_captcha = register_user_form.text_input(
                fields.get("Captcha", "Captcha"), autocomplete='off'
            ).strip()
            register_user_form.image(
                Helpers.generate_captcha('register_user_captcha', self.secret_key)
            )
        if use_cols:
            cols = register_user_form.columns([1, 1.5, 1], gap="medium")[1]
        else:
            cols = register_user_form
        submit = cols.form_submit_button(
            fields.get('Register', 'Register'),
            use_container_width=True, icon=":material/send:", type="primary"
        )
        register_user_form.write("")
        if submit:
            if two_factor_auth:
                self.__two_factor_auth(new_email, widget='register', fields=fields)
            else:
                return self.authentication_controller.register_user(
                    new_first_name, new_last_name,
                    new_email, new_username,
                    new_password,
                    new_password_repeat,
                    password_hint, pre_authorized,
                    domains, user_roles, callback,
                    captcha, entered_captcha
                )
        if two_factor_auth and st.session_state.get('2FA_check_register'):
            del st.session_state['2FA_check_register']
            return self.authentication_controller.register_user(
                new_first_name, new_last_name,
                new_email, new_username,
                new_password, new_password_repeat,
                password_hint, pre_authorized,
                domains, user_roles, callback, captcha,
                entered_captcha
            )
        return None, None, None

    # Reset password
    def reset_password(
        self, username: str, location: Literal['main', 'sidebar'] = 'main',
        fields: Optional[Dict[str, str]] = None, clear_on_submit: bool = False,
        key: str = 'Reset password', callback: Optional[Callable] = None,
        container_css: Optional[str] = None, use_cols: bool = True
    ) -> Optional[bool]:
        """
        Renders a password reset widget.

        Parameters
        ----------
        username : str
            Username of the user whose password is being reset.
        location : {'main', 'sidebar'}, default='main'
            Location where the password reset widget is rendered.
        fields : dict, optional
            Custom labels for form fields and buttons.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Reset password'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.
        container_css : str, optional
            CSS styles to be applied to the container.
        use_cols : bool, default=True
            If True, uses columns for buttons.

        Returns
        -------
        bool or None
            - True if the password reset was successful.
            - None if the reset failed or was not attempted.
        """
        if not st.session_state.get('authentication_status'):
            raise ResetError('User must be logged in to use the reset password widget')
        if fields is None:
            fields = {'Form name':'Reset password', 'Current password':'Current password',
                      'New password':'New password','Repeat password':'Repeat password',
                      'Reset':'Reset'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not container_css:
            container_css = """
                {
                    border-radius: 1rem;
                    border: 2px solid #49485611;
                    box-shadow: 1px 1px 3px #49485621;
                    padding: 1em 1.5em;
                }
            """
        with stylable_container(
            key="reset_password_container",
            css_styles=container_css,
        ):
            if location == 'main':
                reset_password_form = st.form(key=key, clear_on_submit=clear_on_submit, border=False)
            else:
                reset_password_form = st.sidebar.form(
                    key=key, clear_on_submit=clear_on_submit, border=False
                )
        reset_password_form.markdown(
            f"<h4 style='text-align: center;'>{fields.get('Form name', 'Reset password')}</h4>",
            unsafe_allow_html=True
        )
        password = reset_password_form.text_input(
            fields.get('Current password', 'Current password'), type='password', autocomplete='off'
        ).strip()
        password_instructions = self.attrs.get(
            'password_instructions', params.PASSWORD_INSTRUCTIONS
        )
        new_password = reset_password_form.text_input(
            fields.get('New password', 'New password'),
            type='password',
            help=password_instructions,
            autocomplete='off'
        ).strip()
        new_password_repeat = reset_password_form.text_input(
            fields.get('Repeat password', 'Repeat password'),
            type='password',
            autocomplete='off'
        ).strip()
        if use_cols:
            cols = reset_password_form.columns([1, 1.5, 1], gap="medium")[1]
        else:
            cols = reset_password_form
        submit = cols.form_submit_button(
            fields.get('Reset', 'Reset'),
            use_container_width=True, icon=":material/send:", type="primary"
        )
        reset_password_form.write("")
        if submit:
            if self.authentication_controller.reset_password(
                username, password, new_password, new_password_repeat, callback
            ):
                return True
        return None

    # Two-factor authentication
    def __two_factor_auth(
        self, email: str, content: Optional[Dict[str, Any]] = None,
        fields: Optional[Dict[str, str]] = None, widget: Optional[str] = None
    ) -> None:
        """
        Renders a two-factor authentication widget.

        Parameters
        ----------
        email : str
            Email address to which the two-factor authentication code is sent.
        content : dict, optional
            Optional content to save in session state.
        fields : dict, optional
            Custom labels for form fields and buttons.
        widget : str, optional
            Widget name used as a key in session state variables.
        """
        self.authentication_controller.generate_two_factor_auth_code(email, widget)
        @st.dialog(fields.get('Dialog name', 'Verification code'))
        def two_factor_auth_form():
            code = st.text_input(fields.get('Code', 'Code'),
                                 help='Please enter the code sent to your email'
                                 if 'Instructions' not in fields else fields['Instructions'],
                                 autocomplete='off')
            if st.button(
                fields.get('Submit', 'Submit'),
                use_container_width=True, icon=":material/send:", type="primary"
            ):
                if self.authentication_controller.check_two_factor_auth_code(code, content, widget):
                    st.rerun()
                else:
                    st.error(fields.get('Error', 'Code is incorrect'), icon=":material/close:")
        two_factor_auth_form()

    # Update user details
    def update_user_details(
        self, username: str, location: Literal['main', 'sidebar'] = 'main',
        fields: Optional[Dict[str, str]] = None, roles: Optional[List[str]] = None,
        clear_on_submit: bool = False, key: str = 'Update user details',
        callback: Optional[Callable] = None, container_css: Optional[str] = None,
        use_cols: bool = True
    ) -> bool:
        """
        Renders an update user details widget.

        Parameters
        ----------
        username : str
            Username of the user whose details are being updated.
        location : {'main', 'sidebar'}, default='main'
            Location where the update user details widget is rendered.
        fields : dict, optional
            Custom labels for form fields and buttons.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Update user details'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.
        container_css : str, optional
            CSS styles to be applied to the container.
        use_cols : bool, default=True
            If True, uses columns for buttons.

        Returns
        -------
        bool or None
            - True if user details were successfully updated.
            - None if the update failed or was not attempted.
        """
        if not st.session_state.get('authentication_status'):
            raise UpdateError('User must be logged in to use the update user details widget')
        if fields is None:
            fields = {'Form name':'Update user details', 'Field':'Field', 'First name':'First name',
                      'Last name':'Last name', 'Email':'Email', 'New value':'New value',
                      'Update':'Update', 'Roles':'Roles'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not container_css:
            container_css = """
                {
                    border-radius: 1rem;
                    border: 2px solid #49485611;
                    box-shadow: 1px 1px 3px #49485621;
                    padding: 1em 1.5em;
                }
            """
        update_user_details_form = stylable_container(
            key="update_user_container",
            css_styles=container_css,
        )
        # with stylable_container(
        #     key="update_user_container",
        #     css_styles=container_css,
        # ):
        #     if location == 'main':
        #         update_user_details_form = st.form(
        #             key=key, clear_on_submit=clear_on_submit, border=False
        #         )
        #     else:
        #         update_user_details_form = st.sidebar.form(
        #             key=key, clear_on_submit=clear_on_submit, border=False
        #         )
        update_user_details_form.markdown(
            f"<h4 style='text-align: center;'>{fields.get('Form name', 'Update user details')}</h4>",   # pylint: disable=line-too-long
            unsafe_allow_html=True
        )
        update_user_details_form_fields = [
            fields.get("First name", "Firstname"),
            fields.get("Last name", "Lastname"),
            fields.get("Email", "Email"),
            fields.get("Roles", "Roles")
        ]
        field = update_user_details_form.selectbox(
            fields.get("Field", "Field"), update_user_details_form_fields
        )
        if field == "Roles":
            new_value = update_user_details_form.multiselect(
                fields.get("Roles", "Roles"), options=roles,
            )
        else:
            new_value = update_user_details_form.text_input(
                fields.get("New value", "New value"), autocomplete='off'
            ).strip()
        if update_user_details_form_fields.index(field) == 0:
            field = 'first_name'
        elif update_user_details_form_fields.index(field) == 1:
            field = 'last_name'
        elif update_user_details_form_fields.index(field) == 2:
            field = 'email'
        else:
            field = 'roles'
        if use_cols:
            cols = update_user_details_form.columns([1, 1.5, 1], gap="medium")[1]
        else:
            cols = update_user_details_form
        submit = cols.button(
            fields.get('Update', 'Update'),
            use_container_width=True, icon=":material/send:", type="primary"
        )
        update_user_details_form.write("")
        if submit:
            if self.authentication_controller.update_user_details(
                username, field, new_value, callback
            ):
                # self.cookie_controller.set_cookie()
                return True
