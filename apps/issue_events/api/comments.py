from typing import Literal

from django.http import Http404, HttpResponse
from ninja import Schema, Status
from ninja.errors import HttpError
from ninja.pagination import paginate

from glitchtip.api.authentication import AuthHttpRequest
from glitchtip.api.permissions import (
    has_permission,
    scoped_org_id,
)

from ..models import Comment, Issue
from ..schema import CommentSchema
from . import router


def get_queryset(request: AuthHttpRequest, issue_id: int):
    org_id = scoped_org_id(request)
    if org_id is None:
        # Both decorators refuse a caller who is not a member of the issue's
        # organization, so the only way through with no resolved org is that
        # the issue does not exist. Nothing to return, and the caller gets the
        # 404 they would have got from a membership-filtered queryset.
        return Comment.objects.none()
    return Comment.objects.select_related("user").filter(
        issue__project__organization_id=org_id, issue__id=issue_id
    )


class PostCommentSchema(Schema):
    data: dict[Literal["text"], str]


@router.get(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/comments/",
    response=list[CommentSchema],
    by_alias=True,
)
@has_permission(["event:read", "event:admin"])
@paginate
async def list_organization_comments(
    request: AuthHttpRequest,
    response: HttpResponse,
    issue_id: int,
    organization_slug: str,
):
    return get_queryset(request, issue_id)


@router.post(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/comments/",
    response={201: CommentSchema},
    by_alias=True,
)
@has_permission(["event:write", "event:admin"])
async def add_organization_comment(
    request: AuthHttpRequest,
    organization_slug: str,
    issue_id: int,
    payload: PostCommentSchema,
):
    try:
        issue = await Issue.objects.aget(
            id=issue_id, project__organization_id=scoped_org_id(request)
        )
    except Issue.DoesNotExist:
        raise Http404()

    user_id = request.auth.user_id
    comment = await Comment.objects.acreate(
        text=payload.data["text"],
        issue=issue,
        user_id=user_id,
    )

    return Status(201, await Comment.objects.select_related("user").aget(id=comment.id))


@router.put(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/comments/{int:comment_id}/",
    response=CommentSchema,
    by_alias=True,
)
@has_permission(["event:write", "event:admin"])
async def update_organization_comment(
    request: AuthHttpRequest,
    organization_slug: str,
    issue_id: int,
    comment_id: int,
    payload: PostCommentSchema,
):
    try:
        comment = await get_queryset(request, issue_id).aget(id=comment_id)
    except Comment.DoesNotExist:
        raise Http404()

    comment.text = payload.data["text"]
    await comment.asave()

    return comment


@router.delete(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/comments/{int:comment_id}/",
    response={204: None},
    by_alias=True,
)
@has_permission(["event:admin"])
async def delete_organization_comment(
    request: AuthHttpRequest,
    organization_slug: str,
    issue_id: int,
    comment_id: int,
):
    try:
        comment = await get_queryset(request, issue_id).aget(id=comment_id)
    except Comment.DoesNotExist:
        raise Http404()
    await comment.adelete()

    return Status(204, None)
