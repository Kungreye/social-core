from uuid import uuid4

from flask_security import logout_user, login_user, current_user

from ..utils import slugify, module_member


USER_FIELDS = ['name', 'email', 'avatar_url', 'profile_url', 'prefile_type']


def get_username(strategy, details, backend, user=None, *args, **kwargs):
    if 'name' not in backend.setting('USER_FIELDS', USER_FIELDS):
        return
    storage = strategy.storage
    social = None
    if user:
        social = backend.strategy.storage.user.get_social_auth_for_user(user).first()

    if not user or (social and social.provider != backend.name):
        email_as_username = strategy.setting('USERNAME_IS_FULL_EMAIL', False)
        uuid_length = strategy.setting('UUID_LENGTH', 16)
        max_length = storage.user.username_max_length()
        do_slugify = strategy.setting('SLUGIFY_USERNAMES', False)
        do_clean = strategy.setting('CLEAN_USERNAMES', True)

        if do_clean:
            override_clean = strategy.setting('CLEAN_USERNAME_FUNCTION')
            if override_clean:
                clean_func = module_member(override_clean)
            else:
                clean_func = storage.user.clean_username
        else:
            clean_func = lambda val: val

        if do_slugify:
            override_slug = strategy.setting('SLUGIFY_FUNCTION')
            if override_slug:
                slug_func = module_member(override_slug)
            else:
                slug_func = slugify
        else:
            slug_func = lambda val: val

        if email_as_username and details.get('email'):
            username = details['email']
        elif details.get('name'):
            username = details['name']
        else:
            username = uuid4().hex

        short_username = (username[:max_length - uuid_length]
                          if max_length is not None
                          else username)
        final_username = slug_func(clean_func(username[:max_length]))

        # Generate a unique username for current user using username
        # as base but adding a unique hash at the end. Original
        # username is cut to avoid any field max_length.
        # The final_username may be empty and will skip the loop.
        while not final_username or \
              storage.user.user_exists(name=final_username):
            username = short_username + uuid4().hex[:uuid_length]
            final_username = slug_func(clean_func(username[:max_length]))
    else:
        final_username = storage.user.get_username(user)
    return {'name': final_username}


def create_user(strategy, details, backend, user=None, *args, **kwargs):
    relogin = False
    if user:
        social = backend.strategy.storage.user.get_social_auth_for_user(user).first()
        if backend.name == social.provider and getattr(
                user, '{}_url'.format(backend.name)) == \
                details.get('profile_url'):
            return {'is_new': False}
        else:
            relogin = True

    fields = dict((name, kwargs.get(name, details.get(name)))
                  for name in backend.setting('USER_FIELDS', USER_FIELDS))
    if not fields:
        return

    user = strategy.create_user(**fields)
    if relogin:
        logout_user()
        login_user(user)

    return {
        'is_new': True,
        'user': user
    }


def user_details(strategy, details, user=None, *args, **kwargs):
    """Update user details using data from provider."""
    if not user:
        return

    changed = False  # flag to track changes
    protected = ('name', 'id', 'pk', 'email') + \
                tuple(strategy.setting('PROTECTED_USER_FIELDS', []))

    # Update user model attributes with the new data sent by the current
    # provider. Update on some attributes is disabled by default, for
    # example username and id fields. It's also possible to disable update
    # on fields defined in SOCIAL_AUTH_PROTECTED_FIELDS.
    for name, value in details.items():
        if value is None or not hasattr(user, name) or name in protected:
            continue

        # Check https://github.com/omab/python-social-auth/issues/671
        current_value = getattr(user, name, None)
        if current_value or current_value == value:
            continue

        changed = True
        setattr(user, name, value)

    if changed:
        strategy.storage.user.changed(user)
