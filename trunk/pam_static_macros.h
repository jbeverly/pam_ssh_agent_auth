#ifndef __PAM_STATIC_MACROS_H
#define __PAM_STATIC_MACROS_H

#ifndef PAM_EXTERN

#ifdef PAM_STATIC

#define PAM_EXTERN static

struct pam_module {
    const char *name;       /* Name of the module */

    /* These are function pointers to the module's key functions.  */

    int (*pam_sm_authenticate)(pam_handle_t *pamh, int flags,
                   int argc, const char **argv);
    int (*pam_sm_setcred)(pam_handle_t *pamh, int flags,
              int argc, const char **argv);
    int (*pam_sm_acct_mgmt)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
    int (*pam_sm_open_session)(pam_handle_t *pamh, int flags,
                   int argc, const char **argv);
    int (*pam_sm_close_session)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
    int (*pam_sm_chauthtok)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
};

#else /* !PAM_STATIC */

#define PAM_EXTERN extern

#endif /* PAM_STATIC */

#endif /* PAM_EXTERN */

#endif /* __PAM_STATIC_MACROS_H */

