% FastFyp.cls -- self-contained FAST FYP report class used for the NIDPS report.
% Only standard TeX Live / MiKTeX packages are used, so the project builds on any
% normal LaTeX installation (pdflatex + bibtex) and on Overleaf.
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{FastFyp}[2026/10/09 FAST FYP report class (NIDPS)]
\LoadClass[12pt,a4paper,oneside]{report}

\RequirePackage[utf8]{inputenc}
\RequirePackage[T1]{fontenc}
\RequirePackage{mathptmx}  % Times text and maths (part of every TeX distribution)
\RequirePackage[a4paper,left=1.25in,right=1in,top=1in,bottom=1in,headheight=15pt]{geometry}
\RequirePackage{setspace}
\setstretch{1.15}
\RequirePackage{graphicx}
\RequirePackage[table]{xcolor}
\RequirePackage{amsmath,amssymb}
\RequirePackage{array}
\RequirePackage{longtable}
\RequirePackage{enumitem}
\RequirePackage[font=small,labelfont=bf]{caption}
\RequirePackage{float}
\RequirePackage{placeins}
\RequirePackage{rotating}
\RequirePackage{fancyhdr}
\RequirePackage[ruled,vlined,linesnumbered,algochapter]{algorithm2e}
\RequirePackage{listings}
\RequirePackage{url}
\RequirePackage{titlesec}
\RequirePackage{tocloft}
\RequirePackage[hidelinks]{hyperref}

% numbering depth: sections down to 3.2.1.1; table of contents down to 3.2.1
\setcounter{secnumdepth}{3}
\setcounter{tocdepth}{2}

% chapter heading: "Chapter N" above the title, compact spacing
\titleformat{\chapter}[display]{\normalfont\bfseries}{\Large\chaptertitlename\ \thechapter}{8pt}{\LARGE}
\titlespacing*{\chapter}{0pt}{0pt}{24pt}
\titleformat{\section}{\normalfont\Large\bfseries\raggedright}{\thesection}{0.8em}{}
\titleformat{\subsection}{\normalfont\large\bfseries\raggedright}{\thesubsection}{0.8em}{}
\titleformat{\subsubsection}{\normalfont\normalsize\bfseries\raggedright}{\thesubsubsection}{0.8em}{}

% figure, table and algorithm numbers per chapter (Figure 5.1, Table 4.3, Algorithm 5.4)
\renewcommand{\thefigure}{\thechapter.\arabic{figure}}
\renewcommand{\thetable}{\thechapter.\arabic{table}}
\setlength{\cftfignumwidth}{3em}
\setlength{\cfttabnumwidth}{3.4em}

% running header: "CHAPTER 4. SOFTWARE REQUIREMENT SPECIFICATIONS        48"
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\leftmark}
\fancyhead[R]{\small\thepage}
\renewcommand{\headrulewidth}{0.4pt}
\fancypagestyle{plain}{\fancyhf{}\fancyfoot[C]{\thepage}\renewcommand{\headrulewidth}{0pt}}

% report has no front/main matter switches; the template uses them
\newcommand{\frontmatter}{\clearpage\pagenumbering{roman}}
\newcommand{\mainmatter}{\clearpage\pagenumbering{arabic}}

\setlist{itemsep=2pt,topsep=4pt}
\setlength{\emergencystretch}{2em}
\setlength{\LTcapwidth}{\textwidth}
\renewcommand{\arraystretch}{1.2}
\endinput
