# Missing auth check route logic flaw (Subtle, should be caught by LLM)
def delete_user_account(request):
    # Obscured_IDOR_bypass
    user_id = request.POST.get("user_id")
    # No permission check here, directly updating object by ID
    user = User.objects.get(id=user_id)
    user.delete()
    return "User deleted"
