---
title: About
icon: fas fa-user
order: 4
description: >-
  Igor Stepansky (iggyp0pi), security researcher at OX Security: agentic AI for
  offensive security, RCE in AI serving frameworks, a Linux kernel
  use-after-free, supply chain and CI/CD bugs. Experience, community, contact.
---

{% include site-counts.html %}

<div class="terminal-quote">
  <div class="terminal-bar" aria-hidden="true"><span></span><span></span><span></span></div>
  <div class="terminal-body">
    <p class="terminal-line" aria-hidden="true"><span class="terminal-prompt">iggyp0pi@blog:~$</span> fortune</p>
    <blockquote>It is better to be a warrior in a garden than a gardener in a war.</blockquote>
    <p class="terminal-source">often attributed to Miyamoto Musashi</p>
    <p class="terminal-line" aria-hidden="true"><span class="terminal-prompt">iggyp0pi@blog:~$</span> <span class="terminal-cursor">▊</span></p>
  </div>
</div>

## whoami

Igor "iggy" Stepansky. Security Researcher at OX Security, where I build <span class="kw">agentic AI for offensive security</span>: autonomous systems that chain vulnerabilities and logic flaws into real attack paths, the way a pentester would, minus the coffee breaks. Before that, Orca Security's Research Pod.

My research has turned up <span class="kw">unauthenticated remote code execution</span> in AI/LLM serving frameworks, a <span class="kw">use-after-free</span> race in the Linux kernel's ksmbd SMB3 server, and a steady stream of <span class="kw">supply chain and CI/CD</span> vulnerabilities across the modern developer stack. Under all of that sit years of hands-on AppSec: SAST, SCA, IaC scanning, secrets detection, malicious-package hunting, and hardening cloud, container and GitHub environments.

The pattern, if there is one: I like high-impact bugs in <span class="kw">infrastructure that is deployed everywhere</span>, I like handing the fix back (a regular CVE contributor to open-source software), and I like to learn by being slightly out of my depth. New domain, new target, new rabbit hole. That's the fun part.

<p class="research-stats about-stats">
  <a class="stat" href="{{ '/research/' | relative_url }}"><span class="stat-num">{{ cve_count }}</span><span class="stat-label">CVEs found</span>{% if pending_count > 0 %}<span class="stat-pending">+{{ pending_count }} pending</span>{% endif %}</a>
  <a class="stat" href="{{ '/talks/' | relative_url }}"><span class="stat-num">{{ talk_count }}</span><span class="stat-label">talks</span>{% if recorded_count > 0 %}<span class="stat-pending">{{ recorded_count }} recorded</span>{% endif %}</a>
</p>

## Experience

<ul class="xp-timeline">
  <li class="xp">
    <span class="xp-when">2026 - present</span>
    <h3 class="xp-role">Security Researcher <span class="xp-at">@ OX Security</span></h3>
    <p>Teaching machines to hack. Autonomous, agentic pentesting at the intersection of offensive security and AI: the detection engines, the decision-making logic, and the research into vulnerability chaining and logic flaws, prototyped and shipped into production alongside engineering and data science.</p>
  </li>
  <li class="xp">
    <span class="xp-when">2025 - 2026</span>
    <h3 class="xp-role">Security Researcher <span class="xp-at">@ Orca Security</span></h3>
    <p>The Research Pod. AppSec, API and Kubernetes research, detection logic for new vulnerabilities and supply-chain threats, and zero-days found and responsibly disclosed along the way, a use-after-free in the Linux kernel's ksmbd among them. Plus the writing, and the conference stages that come with it.</p>
  </li>
  <li class="xp">
    <span class="xp-when">2022 - 2025</span>
    <h3 class="xp-role">Security Engineer <span class="xp-at">@ Axonius</span></h3>
    <p>Where the AppSec muscle was built. Owned security across the full SDLC: SAST, SCA, DAST, IaC and secrets-detection programs, security code reviews for R&amp;D, malicious-package analysis, cross-company remediation, and pentest engagements. The first DEF CON talk happened from here.</p>
  </li>
  <li class="xp">
    <span class="xp-when">2020 - 2022</span>
    <h3 class="xp-role">Cyber Security Analyst <span class="xp-at">@ Rafael Advanced Defense Systems</span></h3>
    <p>Blue team first. SOC monitoring, alert triage and first-response incident investigation across network and endpoint. Knowing what the defenders actually see is still the most useful thing I carry into offense.</p>
  </li>
</ul>

## Community

- **OWASP Israel, CFP committee.** I read the abstracts. Write a good one and I will go to bat for it.
- **BSidesTLV, volunteer staff.** The crew that keeps the con running. Come say hi.
- **Off the security scene.** Volunteered with ELEM (youth in distress) and in elderly community support, 2024.

## Certifications & education

- OSWE (Offensive Security Web Expert), in progress
- AWS Certified Cloud Practitioner
- B.Sc. Computer Science, the Open University of Israel, in progress (the slow way, around everything above)

## Off the clock

Dad life first. Everything after this sentence is a hobby: Brazilian Jiu-Jitsu (chess with chokes) and long runs (a marathon just wasn't long enough), a soldering iron and whatever has a CPU, and whichever new thing I'm learning this month. Three human languages (English, Hebrew, Russian) and more computer ones than is healthy.

## Contact

- GitHub: <https://github.com/iggypopi>
- LinkedIn: <https://www.linkedin.com/in/igor-stepansky>
