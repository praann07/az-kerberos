#!/bin/bash
set -e
mkdir -p ~/pdfbuild
cp "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC/docs/conference_paper.tex" ~/pdfbuild/
cd ~/pdfbuild
pdflatex -interaction=nonstopmode -halt-on-error conference_paper.tex >build1.log 2>&1 || { tail -30 build1.log; exit 1; }
pdflatex -interaction=nonstopmode -halt-on-error conference_paper.tex >build2.log 2>&1 || { tail -30 build2.log; exit 1; }
cp conference_paper.pdf "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC/docs/AZ-Kerberos_paper.pdf"
grep -c "Overfull" build2.log || true
pdfinfo conference_paper.pdf | grep -E "Pages|Page size"
