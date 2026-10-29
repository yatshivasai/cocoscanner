# Publish CocoScanner on GitHub

## 1. Create the repository

1. Sign in to GitHub.
2. Choose **New repository**.
3. Name it `CocoScanner` (or your preferred name).
4. Set visibility to **Public** if you want everyone to view and download it.
5. Do not initialize another README/license if you are uploading these files as-is.

## 2. Upload these project files

Extract this bundle, open the folder in a terminal, then run:

```bash
git init
git add .
git status
git commit -m "Initial CocoScanner release"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/CocoScanner.git
git push -u origin main
```

Replace `YOUR-USERNAME` and the repository name with your actual GitHub values. GitHub may ask you to authenticate in a browser or with GitHub CLI; do not put a password or token directly into source files.

Before committing, carefully inspect `git status`. The `.gitignore` excludes local JSON records, virtual environments, and packet captures, but verify no personal or sensitive files are staged.

## 3. Let people download the source

Once the repository is public, visitors can use **Code → Download ZIP** on the repository page. GitHub also creates source archives for tags/releases.

## 4. Publish a versioned release (recommended)

1. Open the repository's **Releases** section.
2. Choose **Draft a new release**.
3. Create a tag such as `v0.1.0`.
4. Add release notes and publish.

Describe supported Ubuntu versions, setup commands, known limitations, and test status. Do not call it production-ready until live capture, PCAP analysis, and security checks have been validated on target systems.

## 5. Clone and run

After publication, users can run:

```bash
git clone https://github.com/YOUR-USERNAME/CocoScanner.git
cd CocoScanner
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```
