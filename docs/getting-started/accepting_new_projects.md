---
layout: default
title: Accepting new projects
parent: Getting started
nav_order: 1
permalink: /getting-started/accepting-new-projects/
---

## Accepting New Projects

To be accepted to OSS-Fuzz, an open-source project must
have a significant user base and/or be critical to the global IT infrastructure.

To submit a new project:

* [Create a pull request](https://help.github.com/articles/creating-a-pull-request/)
with new `projects/<project_name>/project.yaml` file
([example](https://github.com/google/oss-fuzz/tree/master/projects/libarchive/project.yaml))
giving at least the following information:
  * project homepage.
  * e-mail of the engineering contact person to be CCed on new issues. It should:
      * belong to an established project committer (according to VCS logs).
        If this is not you or the email address differs from VCS, an informal
        e-mail verification will be required.
      * be associated with a Google account
        ([why?]({{ site.baseurl }}/faq/#why-do-you-require-a-google-account-for-authentication)).
        If you use an alternate email address
        [linked to a Google Account](https://support.google.com/accounts/answer/176347?hl=en),
        it will ONLY give you access to filed bugs in
        [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) and
        NOT to [ClusterFuzz]({{ site.baseurl }}/furthur-reading/clusterfuzz)
        dashboard (due to appengine api limitations).
  * Note that `project_name` can only contain alphanumeric characters,
    underscores(_) or dashes(-).

* Once accepted by an OSS-Fuzz project member, follow the
  [New Project Guide]({{ site.baseurl }}/getting-started/new-project-guide/)
  to configure your project.
