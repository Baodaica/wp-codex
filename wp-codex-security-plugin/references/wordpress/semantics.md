# WordPress Security Semantics

wp_ajax_nopriv_*:
- unauthenticated entrypoint

wp_ajax_*:
- authenticated entrypoint
- authentication alone is NOT authorization

admin_post_nopriv_*:
- unauthenticated entrypoint

admin_post_*:
- authenticated entrypoint
- authentication alone is NOT authorization

check_ajax_referer():
- nonce/CSRF control
- NOT authorization

wp_verify_nonce():
- nonce/intention verification
- NOT authorization

check_admin_referer():
- nonce/CSRF control
- NOT proof of Administrator privilege

is_admin():
- WordPress admin request context
- NOT proof that current user is Administrator

current_user_can():
- capability authorization
- inspect exact capability

user_can():
- capability authorization
- inspect user and exact capability

register_rest_route():
- inspect permission_callback

permission_callback => __return_true:
- public REST access

$wpdb->prepare():
- parameterization only if placeholders and parameters are used correctly

sanitize_text_field():
- generic text normalization
- NOT universal SQL, XSS, or filesystem protection

esc_html():
- HTML text-context encoding

esc_attr():
- HTML attribute-context encoding
