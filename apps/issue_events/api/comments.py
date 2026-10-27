from typing import Literal

from django.db.models import QuerySet
from django.http import Http404, HttpResponse
from ninja import Schema, Status

from glitchtip.api.permissions import (
    OrgScopedHttpRequest,
    org_scoped,
    org_scoped_list,
)

from ..models import Comment, Issue
from ..schema import CommentSchema
from . import router


@router.get(
    "/organizations/{slug:organization_id_or_slug}/issues/{int:issue_id}/comments/",
    response=list[CommentSchema],
    by_alias=True,
)
@org_scoped_list(["event:read"], Comment)
async def list_organization_comments(
    request: OrgScopedHttpRequest,
    response: HttpResponse,
    issue_id: int,
    organization_id_or_slug: str,
):
    return Comment.objects.select_related("user").filter(issue_id=issue_id)


class PostCommentSchema(Schema):
    data: dict[Literal["text"], str]


@router.post(
    "/organizations/{slug:organization_id_or_slug}/issues/{int:issue_id}/comments/",
    response={201: CommentSchema},
    by_alias=True,
)
@org_scoped(["event:write", "event:admin"], Issue)
async def add_organization_comment(
    request: OrgScopedHttpRequest,
    qs: QuerySet[Issue],
    organization_id_or_slug: str,
    issue_id: int,
    payload: PostCommentSchema,
):
    try:
        issue = await qs.aget(id=issue_id)
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
    "/organizations/{slug:organization_id_or_slug}/issues/{int:issue_id}/comments/{int:comment_id}/",
    response=CommentSchema,
    by_alias=True,
)
@org_scoped(["event:write", "event:admin"], Comment)
async def update_organization_comment(
    request: OrgScopedHttpRequest,
    qs: QuerySet[Comment],
    organization_id_or_slug: str,
    issue_id: int,
    comment_id: int,
    payload: PostCommentSchema,
):
    try:
        comment = await qs.select_related("user").aget(issue_id=issue_id, id=comment_id)
    except Comment.DoesNotExist:
        raise Http404()

    comment.text = payload.data["text"]
    await comment.asave()

    return comment


@router.delete(
    "/organizations/{slug:organization_id_or_slug}/issues/{int:issue_id}/comments/{int:comment_id}/",
    response={204: None},
    by_alias=True,
)
@org_scoped(["event:admin"], Comment)
async def delete_organization_comment(
    request: OrgScopedHttpRequest,
    qs: QuerySet[Comment],
    organization_id_or_slug: str,
    issue_id: int,
    comment_id: int,
):
    try:
        comment = await qs.aget(issue_id=issue_id, id=comment_id)
    except Comment.DoesNotExist:
        raise Http404()
    await comment.adelete()

    return Status(204, None)
