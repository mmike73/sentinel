#!/usr/bin/env bash
# Builds main.tex → main.pdf (pdflatex + bibtex two-pass)
set -euo pipefail

PAPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="main"
OUT="$PAPER_DIR/$MAIN.pdf"

# ── colours ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
    CYAN='\033[1;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()  { echo -e "${CYAN}▶ ${RESET}${BOLD}$*${RESET}"; }
ok()    { echo -e "${GREEN}✓ ${RESET}$*"; }
warn()  { echo -e "${YELLOW}⚠ ${RESET}$*"; }
die()   { echo -e "${RED}✗ ${RESET}$*" >&2; exit 1; }

# ── dependency check / install ────────────────────────────────────────────────
REQUIRED_PKGS=(
    "texlive-latex-base"
    "texlive-latex-recommended"
    "texlive-latex-extra"
    "texlive-fonts-recommended"
    "texlive-lang-european"  # Romanian babel (romanian.ldf)
    "texlive-lang-other"
    "poppler-utils"          # pdfinfo for page-count reporting
)
REQUIRED_BINS=(pdflatex bibtex)

check_bins() {
    local missing=()
    for bin in "${REQUIRED_BINS[@]}"; do
        command -v "$bin" &>/dev/null || missing+=("$bin")
    done
    echo "${missing[@]:-}"
}

missing_bins=$(check_bins)

if [[ -n "$missing_bins" ]]; then
    warn "Required binaries not found: $missing_bins"

    if [[ "${1:-}" == "--no-install" ]]; then
        die "Install texlive and bibtex then re-run without --no-install."
    fi

    if [[ $EUID -ne 0 ]] && ! command -v sudo &>/dev/null; then
        die "Need root or sudo to install packages. Run as root or install manually:\n  sudo apt-get install ${REQUIRED_PKGS[*]}"
    fi

    info "Installing LaTeX packages (this takes a few minutes)..."
    SUDO=""
    [[ $EUID -ne 0 ]] && SUDO="sudo"
    $SUDO apt-get update -qq
    $SUDO apt-get install -y --no-install-recommends "${REQUIRED_PKGS[@]}" \
        || die "Package installation failed."

    missing_bins=$(check_bins)
    [[ -n "$missing_bins" ]] && die "Still missing after install: $missing_bins"
    ok "LaTeX tools installed."
fi

for bin in "${REQUIRED_BINS[@]}"; do
    ver=$(command -v "$bin")
    ok "Found $bin → $ver"
done

# ── sanity checks ─────────────────────────────────────────────────────────────
[[ -f "$PAPER_DIR/$MAIN.tex" ]]       || die "$MAIN.tex not found in $PAPER_DIR"
[[ -f "$PAPER_DIR/references.bib" ]]  || die "references.bib not found"
[[ -f "$PAPER_DIR/style.sty" ]]       || die "style.sty not found"

for ch in chapter1_introduction chapter2 chapter3 chapter4 chapter6_conclusions; do
    f="$PAPER_DIR/chapters/$ch.tex"
    [[ -f "$f" ]] || warn "Chapter file missing: $f"
done
ok "Source files present."

# ── build ─────────────────────────────────────────────────────────────────────
cd "$PAPER_DIR"

run_pdflatex() {
    local pass="$1"
    info "pdflatex pass $pass..."
    if ! pdflatex -interaction=nonstopmode -halt-on-error "$MAIN.tex" > /tmp/pdflatex_$pass.log 2>&1; then
        echo ""
        warn "pdflatex pass $pass failed. Last 30 lines of log:"
        tail -30 /tmp/pdflatex_$pass.log
        die "Fix the errors above and re-run."
    fi
    ok "pdflatex pass $pass OK."
}

run_bibtex() {
    info "bibtex..."
    if ! bibtex "$MAIN" > /tmp/bibtex.log 2>&1; then
        warn "bibtex reported warnings/errors:"
        cat /tmp/bibtex.log
        # bibtex exits non-zero on warnings; only abort on actual errors
        grep -i "error" /tmp/bibtex.log && die "bibtex errors detected."
    fi
    ok "bibtex OK."
}

# Standard LaTeX + BibTeX two-pass sequence:
#   pass 1 → writes .aux with \citation entries
#   bibtex  → reads .aux, writes .bbl
#   pass 2 → reads .bbl, resolves \bibitem
#   pass 3 → resolves forward references (ToC, labels)
run_pdflatex 1
run_bibtex
run_pdflatex 2
run_pdflatex 3

# ── result ────────────────────────────────────────────────────────────────────
if [[ -f "$OUT" ]]; then
    SIZE=$(du -sh "$OUT" | cut -f1)
    PAGES=$(pdfinfo "$OUT" 2>/dev/null | awk '/^Pages:/{print $2}') || PAGES="?"
    echo ""
    ok "PDF built: ${BOLD}$OUT${RESET}  ($SIZE, $PAGES pages)"
else
    die "Build appeared to succeed but $OUT was not created."
fi

# ── optional cleanup ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]] || [[ "${2:-}" == "--clean" ]]; then
    info "Removing auxiliary files..."
    rm -f "$PAPER_DIR"/$MAIN.{aux,bbl,blg,log,out,toc,lof,lot}
    ok "Auxiliary files removed."
fi
