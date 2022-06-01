---
layout: default
title: Accepting new projects
parent: Getting started
nav_order: 1
permalink: /getting-started/accepting-new-projects/
---

# Accepting New Projects

To be accepted to OSS-Fuzz, an open-source project must
have a significant user base and/or be critical to the global IT infrastructure.

To submit a new project, do the following:

1. [Create a pull request](https://help.github.com/articles/creating-a-pull-request/)
with a new `projects/<project_name>/project.yaml` file
([example](https://github.com/google/oss-fuzz/tree/master/projects/libarchive/project.yaml)).
    **Note:** `project_name` can only contain alphanumeric characters,
    underscores(_) or dashes(-).
2. In the file, provide the following information:
  * Your project's homepage.
  * An email address for the engineering contact to be CCed on new issues, satisfying the following:
       * The address belongs to an established project committer (according to VCS logs).
        If the address isn't you, or if the address differs from VCS, we'll require an informal
        email verification.
       * The address is associated with a Google account
        ([why?]({{ site.baseurl }}/faq/#why-do-you-require-a-google-account-for-authentication)).
        If you use an alternate email address
        [linked to a Google Account](https://support.google.com/accounts/answer/176347?hl=en),
        you'll only get access to [filed bugs in the issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list), not to the [ClusterFuzz]({{ site.baseurl }}/further-reading/clusterfuzz)
        dashboard. This is due to appengine API limitations.
3. Once your project is accepted, configure it by following the
  [New Project Guide]({{ site.baseurl }}/getting-started/new-project-guide/).
