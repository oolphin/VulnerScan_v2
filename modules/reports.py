#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAB-SEC - Module de génération de rapports PDF professionnels
Corrigé pour afficher correctement les CVE
"""

import os
import logging
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, send_file

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import REPORTS_DIR
from modules.auth import require_auth

logger = logging.getLogger('labsec')
reports_bp = Blueprint('reports', __name__)

# Couleurs LAB-SEC
PRIMARY_DARK  = (10,  15,  30)
PRIMARY_BLUE  = (6,  182, 212)
ACCENT_BLUE   = (30,  80, 162)
WHITE         = (255, 255, 255)
GRAY_BG       = (245, 247, 252)
GRAY_TEXT     = (80,  90, 110)
GRAY_LIGHT    = (200, 210, 220)
GRAY_MID      = (140, 150, 165)

SEV_COLORS = {
    'critical': (220,  38,  38),
    'high':     (245, 158,  11),
    'medium':   (234, 179,   8),
    'low':      ( 16, 185, 129),
    'info':     (100, 116, 139),
}

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, Color
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def _hex(rgb):
    r, g, b = rgb
    return HexColor(f'#{r:02x}{g:02x}{b:02x}')


class LabSecPageCanvas:
    def __init__(self, target):
        self.target = target

    def __call__(self, canvas, doc):
        page_num = canvas.getPageNumber()
        if page_num == 1:
            return
        w, h = A4
        canvas.saveState()
        canvas.setFillColor(_hex(PRIMARY_DARK))
        canvas.rect(0, h - 18*mm, w, 18*mm, fill=1, stroke=0)
        canvas.setFillColor(_hex(PRIMARY_BLUE))
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(12*mm, h - 11*mm, "LAB-SEC")
        canvas.setFillColor(_hex(WHITE))
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 12*mm, h - 11*mm,
                               f"Security Assessment Report  -  {self.target}")
        canvas.setFillColor(_hex(GRAY_BG))
        canvas.rect(0, 0, w, 12*mm, fill=1, stroke=0)
        canvas.setFillColor(_hex(GRAY_TEXT))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(12*mm, 4*mm, "CONFIDENTIEL - Usage interne uniquement")
        canvas.drawRightString(w - 12*mm, 4*mm,
                               f"Page {page_num}  -  {datetime.now().strftime('%d/%m/%Y')}")
        canvas.setStrokeColor(_hex(GRAY_LIGHT))
        canvas.setLineWidth(0.5)
        canvas.line(12*mm, 12*mm, w - 12*mm, 12*mm)
        canvas.restoreState()


def _build_styles():
    styles = getSampleStyleSheet()
    base = dict(fontName='Helvetica', fontSize=9, leading=13, textColor=_hex(GRAY_TEXT))
    custom = {
        'h1': ParagraphStyle('h1', fontName='Helvetica-Bold', fontSize=16,
                             leading=20, textColor=_hex(PRIMARY_DARK), spaceAfter=4),
        'h2': ParagraphStyle('h2', fontName='Helvetica-Bold', fontSize=12,
                             leading=16, textColor=_hex(ACCENT_BLUE), spaceBefore=10, spaceAfter=4),
        'h3': ParagraphStyle('h3', fontName='Helvetica-Bold', fontSize=10,
                             leading=14, textColor=_hex(PRIMARY_DARK), spaceBefore=6, spaceAfter=2),
        'body': ParagraphStyle('body', **base, spaceAfter=6),
        'body_small': ParagraphStyle('body_small', **{**base, 'fontSize': 8, 'leading': 11}),
        'code': ParagraphStyle('code', fontName='Courier', fontSize=7, leading=10,
                               textColor=_hex((40, 50, 70)),
                               backColor=_hex((235, 240, 248)),
                               borderPad=4, spaceAfter=4),
        'center': ParagraphStyle('center', fontName='Helvetica', fontSize=9,
                                  leading=13, textColor=_hex(GRAY_TEXT), alignment=TA_CENTER),
        'label': ParagraphStyle('label', fontName='Helvetica-Bold', fontSize=8,
                                 textColor=_hex(GRAY_TEXT)),
    }
    return {**{k: styles[k] for k in styles.byName}, **custom}


def _section_title(title, styles):
    return [
        Paragraph(title, styles['h1']),
        HRFlowable(width='100%', thickness=2, color=_hex(PRIMARY_BLUE), spaceAfter=8),
    ]


def _info_table(rows, styles, col_widths=None):
    if not col_widths:
        col_widths = [50*mm, 120*mm]
    data = []
    for k, v in rows:
        data.append([
            Paragraph(f"<b>{k}</b>", styles['label']),
            Paragraph(str(v or '-'), styles['body_small'])
        ])
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), _hex(GRAY_BG)),
        ('GRID', (0, 0), (-1, -1), 0.4, _hex(GRAY_LIGHT)),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    return t


def _draw_cover(canvas, doc, results):
    w, h = A4
    canvas.saveState()

    canvas.setFillColor(_hex(PRIMARY_DARK))
    canvas.rect(0, 0, w, h, fill=1, stroke=0)

    canvas.setFillColor(_hex(PRIMARY_BLUE))
    canvas.rect(0, h - 8*mm, w, 8*mm, fill=1, stroke=0)

    canvas.setFillColor(_hex(ACCENT_BLUE))
    canvas.rect(0, 0, w, 5*mm, fill=1, stroke=0)

    canvas.setFillColor(Color(0.06, 0.71, 0.83, alpha=0.07))
    for cx, cy, r in [
        (w * 0.85, h * 0.75, 80*mm),
        (w * 0.1,  h * 0.2,  50*mm),
        (w * 0.75, h * 0.3,  30*mm),
    ]:
        canvas.circle(cx, cy, r, fill=1, stroke=0)

    canvas.setFillColor(_hex(PRIMARY_BLUE))
    canvas.setFont("Helvetica-Bold", 52)
    canvas.drawCentredString(w / 2, h * 0.72, "LAB-SEC")

    canvas.setFillColor(_hex(WHITE))
    canvas.setFont("Helvetica", 16)
    canvas.drawCentredString(w / 2, h * 0.68, "Security Assessment Report")

    canvas.setStrokeColor(_hex(PRIMARY_BLUE))
    canvas.setLineWidth(1.5)
    canvas.line(w * 0.25, h * 0.655, w * 0.75, h * 0.655)

    canvas.setFillColor(_hex(GRAY_LIGHT))
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawCentredString(w / 2, h * 0.63, "CIBLE D'EVALUATION")

    canvas.setFillColor(_hex(WHITE))
    canvas.setFont("Helvetica-Bold", 18)
    target = str(results.get('target', 'N/A'))
    if len(target) > 40:
        target = target[:37] + '...'
    canvas.drawCentredString(w / 2, h * 0.59, target)

    risk_level = str(results.get('vulnerabilities', 'low')).lower()
    if risk_level not in SEV_COLORS:
        risk_level = 'low'
    risk_color = SEV_COLORS[risk_level]
    risk_score = results.get('risk_score', 0)

    badge_w, badge_h = 90*mm, 22*mm
    bx = (w - badge_w) / 2
    by = h * 0.49

    canvas.setFillColor(_hex(risk_color))
    canvas.roundRect(bx, by, badge_w, badge_h, 4*mm, fill=1, stroke=0)

    canvas.setFillColor(_hex(WHITE))
    canvas.setFont("Helvetica-Bold", 13)
    canvas.drawCentredString(w / 2, by + badge_h - 10*mm,
                             f"NIVEAU DE RISQUE : {risk_level.upper()}")
    canvas.setFont("Helvetica", 10)
    canvas.drawCentredString(w / 2, by + 5*mm, f"Score de risque global : {risk_score} / 100")

    meta_y = h * 0.38
    canvas.setFillColor(_hex(GRAY_MID))

    scan_ts = str(results.get('timestamp', ''))[:16].replace('T', ' ')
    gen_ts  = datetime.now().strftime('%d/%m/%Y %H:%M')

    infos = [
        ("Date du scan",      scan_ts   or '-'),
        ("Rapport genere le", gen_ts),
        ("Ports ouverts",     str(results.get('open_ports', 0))),
        ("Services detectes", str(results.get('services', 0))),
    ]
    for i, (label, value) in enumerate(infos):
        row_y = meta_y - i * 8*mm
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(_hex(PRIMARY_BLUE))
        canvas.drawString(w * 0.3, row_y, label + " :")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_hex(WHITE))
        canvas.drawString(w * 0.52, row_y, value)

    canvas.setFillColor(Color(0, 0, 0, alpha=0.4))
    canvas.rect(20*mm, 10*mm, w - 40*mm, 12*mm, fill=1, stroke=0)
    canvas.setFillColor(_hex(GRAY_LIGHT))
    canvas.setFont("Helvetica-BoldOblique", 7.5)
    canvas.drawCentredString(w / 2, 14*mm,
                             "DOCUMENT CONFIDENTIEL - Usage exclusivement interne - Ne pas diffuser")
    canvas.restoreState()


def _extract_cves_from_vulns(vulns, module_results):
    """Extrait toutes les CVE des vulnérabilités et des résultats des modules"""
    cves = []
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,})', re.IGNORECASE)
    
    # Chercher dans les vulnérabilités principales
    for vuln in vulns:
        # Si la vulnérabilité a déjà un champ cve
        if vuln.get('cve'):
            cve_id = vuln['cve']
            if cve_id and cve_id not in [c['id'] for c in cves]:
                cves.append({
                    'id': cve_id.upper(),
                    'severity': vuln.get('severity', 'medium'),
                    'cvss': vuln.get('cvss', 'N/A'),
                    'description': vuln.get('description', '')[:200],
                    'source': vuln.get('service', 'unknown')
                })
        
        # Chercher des CVE dans la description
        description = vuln.get('description', '')
        for match in cve_pattern.findall(description):
            cve_id = match.upper()
            if cve_id not in [c['id'] for c in cves]:
                cves.append({
                    'id': cve_id,
                    'severity': vuln.get('severity', 'medium'),
                    'cvss': vuln.get('cvss', 'N/A'),
                    'description': description[:200],
                    'source': vuln.get('service', 'unknown')
                })
    
    # Chercher dans les résultats des modules
    for module in module_results:
        findings = module.get('findings', [])
        output = module.get('output', '')
        
        # Dans les findings du module
        for finding in findings:
            description = finding.get('description', '')
            for match in cve_pattern.findall(description):
                cve_id = match.upper()
                if cve_id not in [c['id'] for c in cves]:
                    cves.append({
                        'id': cve_id,
                        'severity': finding.get('severity', 'medium'),
                        'cvss': finding.get('cvss', 'N/A'),
                        'description': description[:200],
                        'source': module.get('module', 'unknown')
                    })
        
        # Dans la sortie brute du module
        for match in cve_pattern.findall(output):
            cve_id = match.upper()
            if cve_id not in [c['id'] for c in cves]:
                cves.append({
                    'id': cve_id,
                    'severity': 'medium',  # Sévérité par défaut si non spécifiée
                    'cvss': 'N/A',
                    'description': f"CVE détectée par {module.get('module', 'unknown')}",
                    'source': module.get('module', 'unknown')
                })
    
    # Supprimer les doublons et trier par sévérité
    unique_cves = []
    seen_ids = set()
    
    for cve in cves:
        if cve['id'] not in seen_ids:
            seen_ids.add(cve['id'])
            unique_cves.append(cve)
    
    # Trier par sévérité (critical d'abord)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    unique_cves.sort(key=lambda x: severity_order.get(x['severity'], 5))
    
    return unique_cves


def generate_pdf(results, filename=None):
    """Genere un rapport PDF professionnel. Retourne le chemin du fichier."""
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)

        target_name = str(results.get('target', 'unknown')).replace('/', '-').replace(':', '-')
        if not filename:
            filename = f"LABSEC_Report_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        path = os.path.join(REPORTS_DIR, filename)
        styles = _build_styles()

        details      = results.get('details', {})
        vulns        = details.get('vulns', details.get('findings', []))
        ports        = details.get('ports', [])
        ext_tools    = details.get('external_tools', results.get('module_results', []))
        
        # Extraire les CVE des vulnérabilités et des modules
        cves = _extract_cves_from_vulns(vulns, ext_tools)

        whois_data   = results.get('whois', {})
        geo_data     = results.get('geo', {})

        critical_count = sum(1 for v in vulns if v.get('severity') == 'critical')
        high_count     = sum(1 for v in vulns if v.get('severity') == 'high')
        medium_count   = sum(1 for v in vulns if v.get('severity') == 'medium')
        low_count      = sum(1 for v in vulns if v.get('severity') == 'low')

        risk_level = str(results.get('vulnerabilities', 'low')).lower()
        if risk_level not in SEV_COLORS:
            risk_level = 'low'

        story = []
        story.append(PageBreak())

        # TABLE DES MATIERES
        story += _section_title("Table des Matieres", styles)
        story.append(Spacer(1, 6*mm))
        toc_items = [
            ("1", "Resume Executif",              "3"),
            ("2", "Informations sur la Cible",    "4"),
            ("3", "Ports et Services Ouverts",    "5"),
            ("4", "Vulnerabilites Detectees",     "6"),
            ("5", "CVE Identifiees",              "7"),
            ("6", "Resultats des Outils Externes","8"),
            ("7", "Recommandations de Securite",  "9"),
        ]
        toc_data = [["#", "Section", "Page"]] + toc_items
        toc_table = Table(toc_data, colWidths=[12*mm, 140*mm, 18*mm])
        toc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), _hex(PRIMARY_DARK)),
            ('TEXTCOLOR', (0, 0), (-1, 0), _hex(WHITE)),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [_hex(WHITE), _hex(GRAY_BG)]),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.4, _hex(GRAY_LIGHT)),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(toc_table)
        story.append(PageBreak())

        # RESUME EXECUTIF
        story += _section_title("1. Resume Executif", styles)
        open_ports_count = results.get('open_ports', 0)
        services_count   = results.get('services', 0)
        exec_text = (
            f"Ce rapport presente les resultats d'une evaluation de securite realisee sur la cible "
            f"<b>{results.get('target', 'N/A')}</b>. "
            f"L'analyse a permis d'identifier <b>{len(vulns)}</b> vulnerabilite(s) et "
            f"<b>{len(cves)}</b> CVE(s) sur <b>{open_ports_count}</b> port(s) ouvert(s) et "
            f"<b>{services_count}</b> service(s). "
            f"Le niveau de risque global est <b>{risk_level.upper()}</b> "
            f"(score : <b>{results.get('risk_score', 0)}/100</b>)."
        )
        story.append(Paragraph(exec_text, styles['body']))
        story.append(Spacer(1, 6*mm))

        vuln_summary = [
            ["CRITIQUE", "ELEVE", "MOYEN", "FAIBLE", "TOTAL"],
            [str(critical_count), str(high_count), str(medium_count),
             str(low_count), str(len(vulns))],
        ]
        vs_table = Table(vuln_summary, colWidths=[34*mm] * 5)
        vs_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), _hex(SEV_COLORS['critical'])),
            ('BACKGROUND', (1, 0), (1, 0), _hex(SEV_COLORS['high'])),
            ('BACKGROUND', (2, 0), (2, 0), _hex(SEV_COLORS['medium'])),
            ('BACKGROUND', (3, 0), (3, 0), _hex(SEV_COLORS['low'])),
            ('BACKGROUND', (4, 0), (4, 0), _hex(ACCENT_BLUE)),
            ('BACKGROUND', (0, 1), (-1, 1), _hex(PRIMARY_DARK)),
            ('TEXTCOLOR', (0, 0), (-1, -1), _hex(WHITE)),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, 1), 20),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, 0), 6),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('TOPPADDING', (0, 1), (-1, 1), 10),
            ('BOTTOMPADDING', (0, 1), (-1, 1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, _hex(WHITE)),
        ]))
        story.append(vs_table)
        story.append(Spacer(1, 8*mm))

        story.append(Paragraph("Indicateurs Cles", styles['h2']))
        kpi_rows = [
            ("Cible evaluee",      results.get('target', '-')),
            ("Date du scan",       str(results.get('timestamp', ''))[:16].replace('T', ' ') or '-'),
            ("Score de risque",    f"{results.get('risk_score', 0)} / 100"),
            ("Niveau de risque",   risk_level.upper()),
            ("Ports ouverts",      str(open_ports_count)),
            ("Services identifies",str(services_count)),
            ("Vulnerabilites",     str(len(vulns))),
            ("CVE referencees",    str(len(cves))),
        ]
        story.append(_info_table(kpi_rows, styles))
        story.append(PageBreak())

        # INFORMATIONS SUR LA CIBLE
        story += _section_title("2. Informations sur la Cible", styles)

        story.append(Paragraph("Informations WHOIS", styles['h2']))
        whois_parsed  = whois_data.get('parsed', {})
        whois_dates   = whois_data.get('dates', {})
        whois_ns      = whois_data.get('name_servers', [])
        whois_status  = whois_data.get('status', [])
        whois_contact = whois_data.get('contacts', {})

        if whois_parsed or whois_dates:
            whois_rows = [
                ("Domaine / IP",    whois_data.get('domain', results.get('target', '-'))),
                ("TLD",             whois_data.get('tld', '-')),
                ("Serveur WHOIS",   whois_data.get('whois_server', '-')),
                ("Registrar",       whois_parsed.get('registrar', '-')),
                ("URL Registrar",   whois_parsed.get('registrar_url', '-')),
                ("Creation",        whois_dates.get('creation', '-')),
                ("Expiration",      whois_dates.get('expiry', '-')),
                ("Derniere MAJ",    whois_dates.get('updated', '-')),
                ("DNSSEC",          whois_parsed.get('dnssec', '-')),
                ("Serveurs DNS",    ', '.join(whois_ns) if whois_ns else '-'),
                ("Statut",          ' | '.join(whois_status[:3]) if whois_status else '-'),
            ]
            story.append(_info_table(whois_rows, styles))
        else:
            story.append(Paragraph("Donnees WHOIS non disponibles pour cette cible.", styles['body']))

        if whois_contact:
            story.append(Spacer(1, 4*mm))
            story.append(Paragraph("Contacts WHOIS", styles['h2']))
            for ctype, cinfo in whois_contact.items():
                story.append(Paragraph(ctype.capitalize(), styles['h3']))
                contact_rows = [(k.replace('_', ' ').title(), v) for k, v in cinfo.items()]
                story.append(_info_table(contact_rows, styles))

        if geo_data:
            story.append(Spacer(1, 4*mm))
            story.append(Paragraph("Geolocalisation IP", styles['h2']))
            geo_rows = [
                ("Pays",         geo_data.get('country', '-')),
                ("Code pays",    geo_data.get('country_code', '-')),
                ("Region",       geo_data.get('region', '-')),
                ("Ville",        geo_data.get('city', '-')),
                ("FAI / ISP",    geo_data.get('isp', '-')),
                ("Organisation", geo_data.get('org', '-')),
                ("ASN",          geo_data.get('as', '-')),
                ("Coordonnees",  f"{geo_data.get('lat', '-')}, {geo_data.get('lon', '-')}"),
            ]
            story.append(_info_table(geo_rows, styles))

        dns_data = results.get('dns', {})
        if dns_data:
            story.append(Spacer(1, 4*mm))
            story.append(Paragraph("Resolution DNS", styles['h2']))
            dns_rows = []
            if dns_data.get('resolved_ips'):
                dns_rows.append(("IPs resolues", ', '.join(dns_data['resolved_ips'])))
            if dns_data.get('reverse_dns'):
                rd = dns_data['reverse_dns']
                dns_rows.append(("Reverse DNS", rd.get('hostname', '-')))
            for rtype, rvalues in dns_data.get('records', {}).items():
                if rvalues:
                    dns_rows.append((f"Record {rtype}", ', '.join(str(v) for v in rvalues[:5])))
            if dns_rows:
                story.append(_info_table(dns_rows, styles))

        story.append(PageBreak())

        # PORTS ET SERVICES
        story += _section_title("3. Ports et Services Ouverts", styles)

        if ports:
            port_data = [[
                Paragraph("<b>Port</b>", styles['label']),
                Paragraph("<b>Proto</b>", styles['label']),
                Paragraph("<b>Etat</b>", styles['label']),
                Paragraph("<b>Service</b>", styles['label']),
                Paragraph("<b>Produit / Version</b>", styles['label']),
                Paragraph("<b>Info</b>", styles['label'])
            ]]
            for p in ports:
                port_data.append([
                    Paragraph(str(p.get('port', '')), styles['body_small']),
                    Paragraph(p.get('protocol', 'tcp'), styles['body_small']),
                    Paragraph(p.get('state', 'open'), styles['body_small']),
                    Paragraph(p.get('service', ''), styles['body_small']),
                    Paragraph(f"{p.get('product', '')} {p.get('version', '')}".strip()[:35], styles['body_small']),
                    Paragraph(str(p.get('extrainfo', ''))[:30], styles['body_small']),
                ])
            pt = Table(port_data, colWidths=[18*mm, 16*mm, 16*mm, 28*mm, 55*mm, 37*mm])
            pt.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), _hex(PRIMARY_DARK)),
                ('TEXTCOLOR', (0, 0), (-1, 0), _hex(WHITE)),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [_hex(WHITE), _hex(GRAY_BG)]),
                ('GRID', (0, 0), (-1, -1), 0.4, _hex(GRAY_LIGHT)),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (2, -1), 'CENTER'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(pt)
        else:
            story.append(Paragraph("Aucun port ouvert detecte.", styles['body']))

        services_list = details.get('services', [])
        if services_list:
            story.append(Spacer(1, 6*mm))
            story.append(Paragraph("Services Identifies", styles['h2']))
            story.append(Paragraph(', '.join(services_list), styles['body']))

        story.append(PageBreak())

        # VULNERABILITES
        story += _section_title("4. Vulnerabilites Detectees", styles)

        if vulns:
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(v.get('severity', 'info'), 9))

            for i, v in enumerate(sorted_vulns[:30]):
                severity = v.get('severity', 'info').lower()
                sev_color = _hex(SEV_COLORS.get(severity, SEV_COLORS['info']))
                cve_id = v.get('cve', f'VULN-{i+1:03d}')
                vuln_title = f"{cve_id}  -  {v.get('service', 'Service inconnu')} (Port {v.get('port', 'N/A')})"

                header_data = [[
                    Paragraph(
                        f"<font color='white'><b> {severity.upper()} </b></font>",
                        ParagraphStyle('sv', fontName='Helvetica-Bold', fontSize=8,
                                       textColor=_hex(WHITE), backColor=sev_color,
                                       alignment=TA_CENTER, borderPad=2)
                    ),
                    Paragraph(f"<b>{vuln_title}</b>",
                               ParagraphStyle('vt', fontName='Helvetica-Bold', fontSize=9,
                                              textColor=_hex(PRIMARY_DARK))),
                ]]
                ht = Table(header_data, colWidths=[22*mm, 148*mm])
                ht.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), _hex(GRAY_BG)),
                    ('GRID', (0, 0), (-1, -1), 0.5, _hex(GRAY_LIGHT)),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))

                desc = str(v.get('description', 'Aucune description disponible.'))[:400]
                reco = str(v.get('recommendation', 'Appliquer les correctifs de securite.'))[:300]
                cvss = v.get('cvss', '')

                detail_rows = [
                    ("Description", desc),
                    ("Remediation", reco),
                ]
                if cvss:
                    detail_rows.insert(0, ("Score CVSS", str(cvss)))
                if v.get('output'):
                    detail_rows.append(("Sortie", str(v.get('output', ''))[:200]))

                dt = Table(
                    [[Paragraph(f"<b>{k}</b>", styles['label']),
                      Paragraph(val, styles['body_small'])]
                     for k, val in detail_rows],
                    colWidths=[28*mm, 142*mm]
                )
                dt.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), _hex(GRAY_BG)),
                    ('GRID', (0, 0), (-1, -1), 0.4, _hex(GRAY_LIGHT)),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(KeepTogether([ht, dt, Spacer(1, 4*mm)]))

            if len(vulns) > 30:
                story.append(Paragraph(
                    f"<i>... et {len(vulns) - 30} vulnerabilite(s) supplementaire(s).</i>",
                    styles['body_small']
                ))
        else:
            story.append(Paragraph("Aucune vulnerabilite identifiee lors de ce scan.", styles['body']))

        story.append(PageBreak())

        # CVE (corrigé)
        story += _section_title("5. CVE Identifiees", styles)

        if cves:
            cve_data = [[
                Paragraph("<b>CVE ID</b>", styles['label']),
                Paragraph("<b>Severite</b>", styles['label']),
                Paragraph("<b>Score CVSS</b>", styles['label']),
                Paragraph("<b>Description</b>", styles['label']),
                Paragraph("<b>Source</b>", styles['label']),
            ]]
            
            for c in cves[:40]:
                severity_badge = f"<font color='white'><b>{c['severity'].upper()}</b></font>"
                cve_data.append([
                    Paragraph(f"<b>{c['id']}</b>", styles['body_small']),
                    Paragraph(
                        severity_badge,
                        ParagraphStyle('cve-sev', fontName='Helvetica-Bold', fontSize=7,
                                     textColor=_hex(WHITE), 
                                     backColor=_hex(SEV_COLORS.get(c['severity'], SEV_COLORS['info'])),
                                     alignment=TA_CENTER, borderPad=2)
                    ),
                    Paragraph(str(c['cvss']), styles['body_small']),
                    Paragraph(str(c['description'])[:150], styles['body_small']),
                    Paragraph(str(c['source']), styles['body_small']),
                ])
            
            ct = Table(cve_data, colWidths=[32*mm, 20*mm, 18*mm, 65*mm, 25*mm])
            ct.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), _hex(PRIMARY_DARK)),
                ('TEXTCOLOR', (0, 0), (-1, 0), _hex(WHITE)),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [_hex(WHITE), _hex(GRAY_BG)]),
                ('GRID', (0, 0), (-1, -1), 0.4, _hex(GRAY_LIGHT)),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(ct)
            
            if len(cves) > 40:
                story.append(Paragraph(
                    f"<i>... et {len(cves) - 40} CVE supplementaires.</i>",
                    styles['body_small']
                ))
        else:
            story.append(Paragraph("Aucune CVE n'a ete identifiee lors de ce scan.", styles['body']))

        story.append(PageBreak())

        # OUTILS EXTERNES
        story += _section_title("6. Resultats des Outils Externes", styles)

        if ext_tools:
            for tool in ext_tools:
                tool_name = str(tool.get('module', tool.get('tool', 'Outil'))).upper()
                story.append(Paragraph(tool_name, styles['h2']))

                status = tool.get('status', 'unknown')
                tool_rows = [("Statut", status)]
                if tool.get('duration') is not None:
                    dur = tool['duration']
                    dur_str = f"{float(dur):.1f}s" if str(dur).replace('.','').replace('s','').isdigit() else str(dur)
                    tool_rows.append(("Duree", dur_str))
                story.append(_info_table(tool_rows, styles))

                findings = tool.get('findings', [])
                if findings:
                    story.append(Spacer(1, 3*mm))
                    story.append(Paragraph(f"Resultats ({len(findings)})", styles['h3']))
                    fd = [[
                        Paragraph("<b>Severite</b>", styles['label']),
                        Paragraph("<b>Description</b>", styles['label']),
                    ]]
                    for f in findings[:15]:
                        fd.append([
                            Paragraph(str(f.get('severity', '-')).upper(), styles['body_small']),
                            Paragraph(str(f.get('description', ''))[:200], styles['body_small']),
                        ])
                    ft = Table(fd, colWidths=[22*mm, 148*mm])
                    ft.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), _hex(PRIMARY_DARK)),
                        ('TEXTCOLOR', (0, 0), (-1, 0), _hex(WHITE)),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [_hex(WHITE), _hex(GRAY_BG)]),
                        ('GRID', (0, 0), (-1, -1), 0.4, _hex(GRAY_LIGHT)),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ]))
                    story.append(ft)

                if tool.get('output'):
                    story.append(Spacer(1, 3*mm))
                    story.append(Paragraph("Sortie brute (extrait)", styles['h3']))
                    raw_text = str(tool['output'])[:1500]
                    raw_text = raw_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(raw_text, styles['code']))

                story.append(Spacer(1, 5*mm))
        else:
            story.append(Paragraph("Aucun outil externe execute lors de ce scan.", styles['body']))

        story.append(PageBreak())

        # RECOMMANDATIONS
        story += _section_title("7. Recommandations de Securite", styles)

        recommendations = []

        if critical_count > 0:
            recommendations.append(('critical', 'IMMEDIAT',
                f"Traiter {critical_count} vulnerabilite(s) critique(s) dans les 24 a 48 heures. "
                f"Ces failles representent un risque d'exploitation immediat."))
        if high_count > 0:
            recommendations.append(('high', 'URGENT',
                f"Corriger {high_count} vulnerabilite(s) elevee(s) dans la semaine. "
                f"Prioriser les services exposes sur Internet."))
        if medium_count > 0:
            recommendations.append(('medium', 'PLANIFIE',
                f"Planifier la remediation de {medium_count} vulnerabilite(s) moyenne(s) dans le mois."))
        if low_count > 0:
            recommendations.append(('low', 'AMELIORATION',
                f"Adresser {low_count} vulnerabilite(s) faible(s) lors du prochain cycle de maintenance."))

        port_numbers = [p.get('port') for p in ports]
        if 21 in port_numbers:
            recommendations.append(('medium', 'FTP',
                "FTP (port 21) detecte. Remplacer par SFTP ou FTPS. Desactiver l'acces anonyme."))
        if 23 in port_numbers:
            recommendations.append(('high', 'TELNET',
                "Telnet (port 23) detecte. Protocole non chiffre. Migrer vers SSH immediatement."))
        if 25 in port_numbers:
            recommendations.append(('medium', 'SMTP',
                "SMTP (port 25) expose. Verifier le relais, activer STARTTLS et SPF/DKIM/DMARC."))
        if 139 in port_numbers or 445 in port_numbers:
            recommendations.append(('high', 'SMB',
                "SMB (port 139/445) expose. Restreindre l'acces, activer la signature SMB, "
                "desactiver SMBv1 (vulnerable a EternalBlue/WannaCry)."))
        if 3389 in port_numbers:
            recommendations.append(('high', 'RDP',
                "RDP (port 3389) accessible. Restreindre via VPN, activer NLA, appliquer MFA."))
        if 22 in port_numbers:
            recommendations.append(('medium', 'SSH',
                "SSH (port 22) expose. Desactiver l'auth par mot de passe, utiliser des cles SSH."))
        if any(p in port_numbers for p in [3306, 5432, 1433, 1521, 27017]):
            recommendations.append(('critical', 'BASE DE DONNEES',
                "Port de base de donnees expose sur le reseau. "
                "Les bases de donnees ne doivent jamais etre accessibles directement."))

        recommendations += [
            ('info', 'BONNES PRATIQUES',
             "Mettre en place des scans de vulnerabilite reguliers et des tests d'intrusion annuels."),
            ('info', 'AUTHENTIFICATION',
             "Deployer l'authentification multi-facteurs (MFA) sur tous les acces administratifs."),
            ('info', 'SUPERVISION',
             "Activer la journalisation centralisee (SIEM) et configurer des alertes sur les evenements de securite."),
            ('info', 'MISES A JOUR',
             "Maintenir un processus de gestion des correctifs avec des delais de remediation definis."),
            ('info', 'SEGMENTATION',
             "Segmenter le reseau (DMZ, VLAN) pour limiter la propagation en cas de compromission."),
        ]

        reco_data = [[
            Paragraph("<b>Priorite</b>", styles['label']),
            Paragraph("<b>Domaine</b>", styles['label']),
            Paragraph("<b>Recommandation</b>", styles['label']),
        ]]
        for severity, domain, text in recommendations:
            sc = SEV_COLORS.get(severity, SEV_COLORS['info'])
            reco_data.append([
                Paragraph(
                    f"<font color='white'><b> {severity.upper()} </b></font>",
                    ParagraphStyle('rs', fontName='Helvetica-Bold', fontSize=7,
                                   textColor=_hex(WHITE), backColor=_hex(sc),
                                   alignment=TA_CENTER, borderPad=2)
                ),
                Paragraph(f"<b>{domain}</b>", styles['body_small']),
                Paragraph(text, styles['body_small']),
            ])

        rt = Table(reco_data, colWidths=[22*mm, 32*mm, 116*mm])
        rt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), _hex(PRIMARY_DARK)),
            ('TEXTCOLOR', (0, 0), (-1, 0), _hex(WHITE)),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [_hex(WHITE), _hex(GRAY_BG)]),
            ('GRID', (0, 0), (-1, -1), 0.4, _hex(GRAY_LIGHT)),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(rt)

        # BUILD
        page_canvas = LabSecPageCanvas(str(results.get('target', '')))

        def on_page(canvas, doc):
            if canvas.getPageNumber() == 1:
                _draw_cover(canvas, doc, results)
            else:
                page_canvas(canvas, doc)

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=15*mm, rightMargin=15*mm,
            topMargin=22*mm, bottomMargin=16*mm,
            title=f"LAB-SEC Report - {results.get('target', '')}",
            author="LAB-SEC Platform",
            subject="Security Assessment Report",
            creator="LAB-SEC v3.2",
        )
        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

        logger.info(f"Rapport PDF genere : {path}")
        return path

    except Exception as e:
        logger.error(f"Erreur generation PDF : {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


@reports_bp.route('/pdf', methods=['POST'])
@require_auth
def generate_pdf_report():
    """Genere et telecharge le rapport PDF."""
    try:
        results = request.json.get('results')
        if not results:
            return jsonify({'error': 'Aucun resultat fourni'}), 400

        target_name = str(results.get('target', 'unknown')).replace('/', '-').replace(':', '-')
        filename = f"LABSEC_Report_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        path = generate_pdf(results, filename)

        if path and os.path.exists(path):
            return send_file(path, as_attachment=True,
                             download_name=filename, mimetype='application/pdf')

        return jsonify({'error': 'Echec de la generation du PDF'}), 500

    except Exception as e:
        logger.error(f"Route PDF error: {e}")
        return jsonify({'error': str(e)}), 500