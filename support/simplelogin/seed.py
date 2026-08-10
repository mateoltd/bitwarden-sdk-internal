"""Seed the pinned SimpleLogin application through its own models."""

import json
import os

from app.contact_utils import create_contact
from app.db import Session
from app.models import (
    Alias,
    ApiKey,
    Contact,
    SLDomain,
    User,
    UserAliasDeleteAction,
)
from server import create_light_app


USER_EMAIL = os.environ.get(
    "SIMPLELOGIN_LAB_USER_EMAIL", "sdk-integration@mailbox.lan"
)
API_KEY_NAME = "bitwarden-sdk-integration"
DOMAINS = ("sl.lan", "aliases.sl.lan")
SEEDED_ALIASES = ("seed-alpha@sl.lan", "seed-beta@aliases.sl.lan")
SEEDED_CONTACT = "seed-contact@example.com"


def ensure_domains() -> None:
    for index, domain in enumerate(DOMAINS):
        sl_domain = SLDomain.get_by(domain=domain)
        if sl_domain is None:
            sl_domain = SLDomain.create(domain=domain)
        sl_domain.premium_only = False
        sl_domain.hidden = False
        sl_domain.order = index
        sl_domain.use_as_reverse_alias = True
    Session.commit()


def ensure_user() -> User:
    user = User.get_by(email=USER_EMAIL)
    if user is None:
        user = User.create(
            email=USER_EMAIL,
            name="Bitwarden SDK integration",
            activated=True,
            lifetime=True,
            alias_delete_action=UserAliasDeleteAction.DeleteImmediately,
            commit=True,
        )
    user.activated = True
    user.disabled = False
    user.lifetime = True
    user.alias_delete_action = UserAliasDeleteAction.DeleteImmediately
    user.flags = user.flags & ~User.FLAG_FREE_DISABLE_CREATE_CONTACTS
    Session.commit()
    return user


def ensure_alias(user: User, email: str, note: str) -> Alias:
    alias = Alias.get_by(email=email)
    if alias is None:
        alias = Alias.create(
            user_id=user.id,
            email=email,
            mailbox_id=user.default_mailbox_id,
        )
    elif alias.user_id != user.id:
        raise RuntimeError(f"seed alias {email} belongs to another user")

    alias.enabled = True
    alias.name = "Seed alias"
    alias.note = note
    alias.pinned = False
    alias.delete_on = None
    alias.delete_reason = None
    Session.commit()
    return alias


def seed() -> dict:
    ensure_domains()
    user = ensure_user()

    aliases = [
        ensure_alias(user, email, f"Seeded by Bitwarden SDK lab ({index})")
        for index, email in enumerate(SEEDED_ALIASES, start=1)
    ]

    Session.query(Contact).filter(Contact.alias_id == aliases[0].id).delete(
        synchronize_session=False
    )
    Session.commit()
    contact_result = create_contact(SEEDED_CONTACT, aliases[0])
    if contact_result.contact is None:
        raise RuntimeError(f"failed to seed contact: {contact_result.error}")

    Session.query(ApiKey).filter(
        ApiKey.user_id == user.id, ApiKey.name == API_KEY_NAME
    ).delete(synchronize_session=False)
    api_key = ApiKey.create(user_id=user.id, name=API_KEY_NAME)
    Session.commit()

    return {
        "api_key": api_key.code,
        "user_email": user.email,
        "seeded_aliases": [alias.email for alias in aliases],
        "seeded_contact": contact_result.contact.website_email,
        "seeded_reverse_alias": contact_result.contact.reply_email,
    }


if __name__ == "__main__":
    with create_light_app().app_context():
        print(json.dumps(seed(), separators=(",", ":")))
