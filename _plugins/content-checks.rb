# frozen_string_literal: true

# Build-time checks for this site. The build fails with a clear message when:
#   1. a post, tab, title, description or the site description contains an
#      em dash (U+2014) or "&mdash;" (house style: no em dashes anywhere);
#   2. a post tagged "CVE Discovered" lacks cve, cvss or component, or has a
#      quoted (non-numeric) cvss. The Research index, home rows and severity
#      pills are generated from those fields.
Jekyll::Hooks.register :site, :post_read do |site|
  problems = []
  em = "—"

  check_text = lambda do |label, text|
    return if text.nil?
    text = text.to_s
    if text.include?(em) || text.include?('&mdash;')
      line = text.lines.index { |l| l.include?(em) || l.include?('&mdash;') }
      problems << "#{label}#{line ? ":#{line + 1}" : ''}: em dash found (house style: no em dashes)"
    end
  end

  check_text.call('_config.yml description', site.config['description'])
  check_text.call('_config.yml tagline', site.config['tagline'])

  tabs = site.collections['tabs'] ? site.collections['tabs'].docs : []
  (site.posts.docs + tabs).each do |doc|
    check_text.call(doc.relative_path, doc.content)
    check_text.call("#{doc.relative_path} (title)", doc.data['title'])
    check_text.call("#{doc.relative_path} (description)", doc.data['description'])
  end

  site.posts.docs.each do |post|
    next unless Array(post.data['tags']).include?('CVE Discovered')

    %w[cve cvss component].each do |key|
      value = post.data[key]
      problems << "#{post.relative_path}: tagged 'CVE Discovered' but missing '#{key}'" if value.nil? || value.to_s.strip.empty?
    end
    cvss = post.data['cvss']
    problems << "#{post.relative_path}: cvss must be an unquoted number, got #{cvss.inspect}" if !cvss.nil? && !cvss.is_a?(Numeric)
  end

  next if problems.empty?

  problems.each { |p| Jekyll.logger.error 'Content check:', p }
  raise Jekyll::Errors::FatalException, "#{problems.size} content check(s) failed; see errors above"
end
