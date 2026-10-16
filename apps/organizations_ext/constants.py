from typing import Literal, TypedDict

from django.db import models

Scopes = Literal[
    "org:read",
    "org:write",
    "org:admin",
    "org:integrations",
    "member:read",
    "member:write",
    "member:admin",
    "team:read",
    "team:write",
    "team:admin",
    "project:read",
    "project:write",
    "project:admin",
    "project:releases",
    "event:read",
    "event:write",
    "event:admin",
]


class Role(TypedDict, total=False):
    id: str
    name: str
    desc: str
    scopes: set[Scopes]
    is_global: bool


# Defines which scopes belong to which role
# Credit to sentry/conf/server.py
ROLES: tuple[Role, ...] = (
    {
        "id": "member",
        "name": "Member",
        "desc": "Members can view and act on events, as well as view most other data within the organization.",
        "scopes": {
            "event:read",
            "event:write",
            "event:admin",
            "project:releases",
            "project:read",
            "org:read",
            "member:read",
            "team:read",
        },
    },
    {
        "id": "admin",
        "name": "Admin",
        "desc": "Admins can create, change, and delete any project, team, alert, and uptime monitor in the organization, and manage team memberships.",
        "scopes": {
            "event:read",
            "event:write",
            "event:admin",
            "org:read",
            "member:read",
            "project:read",
            "project:write",
            "project:admin",
            "project:releases",
            "team:read",
            "team:write",
            "team:admin",
            "org:integrations",
        },
    },
    {
        "id": "manager",
        "name": "Manager",
        "desc": "Everything an admin can do, plus inviting and removing members, changing their roles up to manager, and changing organization settings.",
        "is_global": True,
        "scopes": {
            "event:read",
            "event:write",
            "event:admin",
            "member:read",
            "member:write",
            "member:admin",
            "project:read",
            "project:write",
            "project:admin",
            "project:releases",
            "team:read",
            "team:write",
            "team:admin",
            "org:read",
            "org:write",
            "org:integrations",
        },
    },
    {
        "id": "owner",
        "name": "Organization Owner",
        "desc": "Unrestricted access to the organization, its data, and its settings. Can add, modify, and delete projects and members, as well as make billing and plan changes.",
        "is_global": True,
        "scopes": {
            "org:read",
            "org:write",
            "org:admin",
            "org:integrations",
            "member:read",
            "member:write",
            "member:admin",
            "team:read",
            "team:write",
            "team:admin",
            "project:read",
            "project:write",
            "project:admin",
            "project:releases",
            "event:read",
            "event:write",
            "event:admin",
        },
    },
)


class OrganizationUserRole(models.IntegerChoices):
    MEMBER = 0, "Member"
    ADMIN = 1, "Admin"
    MANAGER = 2, "Manager"
    OWNER = 3, "Owner"  # Many users can be owner but only one primary owner

    @classmethod
    def from_string(cls, string: str):
        for status in cls:
            if status.label.lower() == string.lower():
                return status

    @classmethod
    def get_role(cls, role: int):
        return ROLES[role]
