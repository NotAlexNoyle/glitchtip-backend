from typing import Literal

# The flags for the bitfield (API Key)
SCOPES = (
            "project:read",
            "project:write",
            "project:admin",
            "project:releases",
            "team:read",
            "team:write",
            "team:admin",
            "event:read",
            "event:write",
            "event:admin",
            "org:read",
            "org:write",
            "org:admin",
            "member:read",
            "member:write",
            "member:admin",
            "org:integrations"
        )

# The types for everywhere else (Session Perms)
Scopes = Literal[   
    "project:read", 
    "project:write", 
    "project:admin", 
    "project:releases",
    "team:read", 
    "team:write", 
    "team:admin",
    "event:read", 
    "event:write", 
    "event:admin",
    "org:read", 
    "org:write", 
    "org:admin",
    "member:read", 
    "member:write", 
    "member:admin",
    "org:integrations",
]
