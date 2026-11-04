---
title: Tools
icon: fas fa-screwdriver-wrench
order: 3
description: >-
  Security tooling built by iggyp0pi: ActChain, a supply chain scanner for
  GitHub Actions that maps, scans and pins every action a workflow pulls in.
---

Things I build when the tooling that already exists does not do the job.

{%- assign released = site.data.tools | where: 'status', 'released' -%}
{%- assign upcoming = site.data.tools | where: 'status', 'upcoming' -%}
{%- for tool in released %}
{% include tool-card.html tool=tool %}
{%- endfor %}
{%- if upcoming.size > 0 %}

## In the works
{% for tool in upcoming %}
{% include tool-card.html tool=tool %}
{%- endfor %}
{%- endif %}

<p class="research-foot">More tools are in the works. They land here first.</p>
