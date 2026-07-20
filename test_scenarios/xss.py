from django.utils.safestring import mark_safe

def render_comment(request):
    comment_text = request.POST.get("comment")
    # This is an unescaped user-input render (XSS)
    html_response = "<div>" + comment_text + "</div>"
    return mark_safe(html_response)
