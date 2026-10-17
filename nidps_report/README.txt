NIDPS FYP report - LaTeX project
================================

Build (any TeX Live / MiKTeX installation):

    pdflatex main
    bibtex main
    pdflatex main
    pdflatex main

or simply:  latexmk -pdf main

Overleaf: upload this zip as a new project (New Project > Upload Project) and press Recompile.

Files
  main.tex          front matter (title page, declarations, abstract, summary) and chapter includes
  FastFyp.cls       self-contained report class (page layout, headers, numbering)
  fypbib.bib        references (IEEE style, numbered in order of citation)
  chapters/         ch1to4.tex, ch5.tex, ch6.tex
  Figures/          all images used by the report
  main.bbl          pre-built bibliography, so references resolve even without running bibtex
  main.pdf          the compiled report, for reference
