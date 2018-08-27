# Submit a Patch to oss-fuzz repo

## One-time Setup

1.  Create github account if needed (with @google.com email address, preferably)
    and log in.
1.  To allow “git push” to work, you’ll have to add an SSH key:
    https://help.github.com/articles/connecting-to-github-with-ssh/
1.  Go to https://github.com/google/oss-fuzz and click on “Fork”.
1.  Go to your own fork of the repo, which will be at
    https://github.com/\<git_username\>/oss-fuzz
1.  Click on “clone or download” and pick “Clone with SSH” method (I found that
    easier to use for “git push”). Then copy that URL and run “git clone \<URL\>”
    in terminal. Now you have a local repo, and **your fork** of the remote repo
    will be called “**origin**” in your git config.
1.  Configure a remote repo pointing to the **upstream repo**
    (https://github.com/google/oss-fuzz) so that it’s called “**upstream**”:
    *   cd \<local_oss_fuzz_repo_directory\>/oss-fuzz
    *   git remote add upstream git@github.com:google/oss-fuzz.git
    *   git remote -v

NOTE: For trivial changes it's possible to edit the files in the web UI on the
main project and create a commit + pull request from that.

## Workflow for a Pull Request (Patch)

1.  Go to your repo:
    *   cd \<local_oss_fuzz_repo_directory\>/oss-fuzz
1.  Create a new branch:
    *   git checkout master
    *   git checkout -b new_feature_xyz
1.  Make your changes and commit them locally with “git commit”
1.  Push your changes to your fork on github
    *   git push -u origin HEAD
    *   (This will create a branch of the same name “new_feature_xyz” on your
        fork “origin”).
1.  Open your fork in browser and click on “Compare & pull request” and follow
    the prompts.
1.  If changes are requested to the patch:
    *   make changes to the same local branch
    *   commit them locally with “git commit” (but DO NOT amend!)
    *   git push -u origin HEAD
1.  Once pull request is closed:
    *   Delete “new_feature_xyz” branch on your fork using the “Delete branch”
        button on the pull request
    *   Delete local “new_feature_xyz” branch locally with “git checkout master
        && git branch -D new_feature_xyz”
    *   Sync your local repo and your fork with upstream repo:
        *   git checkout master
        *   git fetch upstream
        *   git merge upstream/master
        *   git push origin master
