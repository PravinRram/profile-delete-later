<div style="display: flex;">
  <img src="static/kklogo.png" alt="KK logo" width="100" height="100" style="border-radius:50%;">
  <h1 style="margin-left:10px;">KampongKonek</h1>
</div>

# KampongKonek
## A platform for fostering long-lasting intergenerational connections
### _Coming Soon_

## Setup:

1. Initialise python virtual environment:

```
python -m venv venv
```
or 
```
python3 -m venv venv
```

then start it

2. Install dependencies:

```
pip install -r requirements.txt
```

3. Create a new git branch for making your changes:

```
git branch branch_name

git checkout branch_name
```

## How to commit:

1. Add all your changes:

```zsh
git add . # Note the leading dot
git commit -m "Commit message here"

git push -u origin branch_name
```

Then go to github, this repo, pull requests tab, and create a new pull request.

## What do if you already made your changes on the master branch
```
git stash -m "temporary message"

git branch branch_name
git checkout branch_name

git stash pop
```
