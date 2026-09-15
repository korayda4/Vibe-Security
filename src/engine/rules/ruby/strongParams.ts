import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'RB-002',
  title: 'Ruby on Rails: mass assignment — params.require only',
  layer: 'backend',
  severity: 'high',
  description:
    'In Rails, `User.create(params[:user])` or `User.update(params[:user])` passes the entire params hash to the model. Attackers can set `admin: true`, `role: \'admin\`, etc. Rails 4+ requires using strong parameters (`params.require(:user).permit(...)`).',
  threat: 'Privilege escalation (become admin), business logic bypass',
  remediation:
    '1) Use strong parameters in every controller: `def user_params; params.require(:user).permit(:name, :email); end`. ' +
    '2) Never call `User.create(params[:user])` directly. ' +
    '3) Use `before_action :authenticate_user!` for protected actions. ' +
    '4) For nested attributes: `.permit(:name, emails_attributes: [:address])`. ' +
    '5) In Rails 5+, `config.load_defaults 5.0` enables `permit_all_parameters = false` by default.',
  references: [
    'https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters',
    'https://guides.rubyonrails.org/security.html#mass-assignment',
  ],
  cwe: 'CWE-915',
  owasp: 'A04:2021 Insecure Design',
  languages: ['ruby'],
  check: (ctx) => {
    const patterns = [
      /\.(?:create|update|update_attributes)\s*\(\s*params\s*[,:]/g,
      /\.(?:create|update|update_attributes)\s*\(\s*params\[:/g,
      /User\.create\s*\(\s*params/g,
    ];
    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
