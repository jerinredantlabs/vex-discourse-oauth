# frozen_string_literal: true

# name: vex-discourse-oauth2
# about: VEX OAuth2 Plugin
# version: 0.3
# authors: Robin Ward & Jacob Palnick
# url: https://git.innovationfirst.net/Robomatter/vex-discourse-oauth2

load File.expand_path('../app/models/vex_license.rb', __FILE__)
load File.expand_path('../app/models/vex_auth_info.rb', __FILE__)

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oauth2_enabled

class ::OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"

  uid do
    if path = SiteSetting.oauth2_callback_user_id_path.split('.')
      recurse(access_token, [*path]) if path.present?
    end
  end

  info do
    if paths = SiteSetting.oauth2_callback_user_info_paths.split('|')
      result = Hash.new
      paths.each do |p|
        segments = p.split(':')
        if segments.length == 2
          key = segments.first
          path = [*segments.last.split('.')]
          result[key] = recurse(access_token, path)
        end
      end
      result
    end
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end

  def recurse(obj, keys)
    return nil if !obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end
end

require 'faraday/logging/formatter'
class OAuth2FaradayFormatter < Faraday::Logging::Formatter
  def request(env)
    warn <<~LOG
      OAuth2 Debugging: request #{env.method.upcase} #{env.url.to_s}

      Headers: #{env.request_headers}

      Body: #{env[:body]}
    LOG
  end

  def response(env)
    warn <<~LOG
      OAuth2 Debugging: response status #{env.status}

      From #{env.method.upcase} #{env.url.to_s}

      Headers: #{env.response_headers}

      Body: #{env[:body]}
    LOG
  end
end

# You should use this register if you want to add custom paths to traverse the user details JSON.
# We'll store the value in the user associated account's extra attribute hash using the full path as the key.
DiscoursePluginRegistry.define_filtered_register :oauth2_basic_additional_json_paths

class ::OAuth2BasicAuthenticator < Auth::ManagedAuthenticator
  def name
    'oauth2_basic'
  end

  def can_revoke?
    SiteSetting.oauth2_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.oauth2_allow_association_change
  end

  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: name,
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.oauth2_client_id
                        opts[:client_secret] = SiteSetting.oauth2_client_secret
                        opts[:provider_ignores_state] = SiteSetting.oauth2_disable_csrf
                        opts[:client_options] = {
                          authorize_url: SiteSetting.oauth2_authorize_url,
                          token_url: SiteSetting.oauth2_token_url,
                          token_method: SiteSetting.oauth2_token_url_method.downcase.to_sym
                        }
                        opts[:authorize_options] = SiteSetting.oauth2_authorize_options.split("|").map(&:to_sym)

                        if SiteSetting.oauth2_authorize_signup_url.present? &&
                            ActionDispatch::Request.new(env).params["signup"].present?
                          opts[:client_options][:authorize_url] = SiteSetting.oauth2_authorize_signup_url
                        end

                        if SiteSetting.oauth2_send_auth_header? && SiteSetting.oauth2_send_auth_body?
                          # For maximum compatibility we include both header and body auth by default
                          # This is a little unusual, and utilising multiple authentication methods
                          # is technically disallowed by the spec (RFC2749 Section 5.2)
                          opts[:client_options][:auth_scheme] = :request_body
                          opts[:token_params] = { headers: { 'Authorization' => basic_auth_header } }
                        elsif SiteSetting.oauth2_send_auth_header?
                          opts[:client_options][:auth_scheme] = :basic_auth
                        else
                          opts[:client_options][:auth_scheme] = :request_body
                        end

                        unless SiteSetting.oauth2_scope.blank?
                          opts[:scope] = SiteSetting.oauth2_scope
                        end

                        if SiteSetting.oauth2_debug_auth && defined? OAuth2FaradayFormatter
                          opts[:client_options][:connection_build] = lambda { |builder|
                            builder.response :logger, Rails.logger, { bodies: true, formatter: OAuth2FaradayFormatter }

                            # Default stack:
                            builder.request :url_encoded             # form-encode POST params
                            builder.adapter Faraday.default_adapter  # make requests with Net::HTTP
                          }
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def walk_path(fragment, segments, seg_index = 0)
    first_seg = segments[seg_index]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash) || fragment.is_a?(Array)
    first_seg = segments[seg_index].scan(/([\d+])/).length > 0 ? first_seg.split("[")[0] : first_seg
    if fragment.is_a?(Hash)
      deref = fragment[first_seg] || fragment[first_seg.to_sym]
    else
      array_index = 0
      if (seg_index > 0)
        last_index = segments[seg_index - 1].scan(/([\d+])/).flatten() || [0]
        array_index = last_index.length > 0 ? last_index[0].to_i : 0
      end
      if fragment.any? && fragment.length >= array_index - 1
        deref = fragment[array_index][first_seg]
      else
        deref = nil
      end
    end

    if (deref.blank? || seg_index == segments.size - 1)
      deref
    else
      seg_index += 1
      walk_path(deref, segments, seg_index)
    end
  end

  def json_walk(result, user_json, prop, custom_path: nil)
    path = custom_path || SiteSetting.public_send("oauth2_json_#{prop}_path")
    if path.present?
      #this.[].that is the same as this.that, allows for both this[0].that and this.[0].that path styles
      path = path.gsub(".[].", ".").gsub(".[", "[")
      segments = parse_segments(path)
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def parse_segments(path)
    segments = [+""]
    quoted = false
    escaped = false

    path.split("").each do |char|
      next_char_escaped = false
      if !escaped && (char == '"')
        quoted = !quoted
      elsif !escaped && !quoted && (char == '.')
        segments.append +""
      elsif !escaped && (char == '\\')
        next_char_escaped = true
      else
        segments.last << char
      end
      escaped = next_char_escaped
    end

    segments
  end

  def log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  def fetch_user_details(token, id)
    user_json_url = SiteSetting.oauth2_user_json_url.sub(':token', token.to_s).sub(':id', id.to_s)
    user_json_method = SiteSetting.oauth2_user_json_url_method

    log("user_json_url: #{user_json_method} #{user_json_url}")

    bearer_token = "Bearer #{token}"
    connection = Excon.new(
      user_json_url,
      headers: { 'Authorization' => bearer_token, 'Accept' => 'application/json' }
    )
    user_json_response = connection.request(method: user_json_method)

    log("user_json_response: #{user_json_response.inspect}")

    if user_json_response.status == 200
      user_json = JSON.parse(user_json_response.body)

      log("user_json: #{user_json}")

      result = {}
      if user_json.present?
        json_walk(result, user_json, :user_id)
        json_walk(result, user_json, :username)
        json_walk(result, user_json, :name)
        json_walk(result, user_json, :email)
        json_walk(result, user_json, :email_verified)
        json_walk(result, user_json, :avatar)

        DiscoursePluginRegistry.oauth2_basic_additional_json_paths.each do |detail|
          prop = "extra:#{detail}"
          json_walk(result, user_json, prop, custom_path: detail)
        end
      end

      vex_id = user_json["data"]["id"]

      if vex_info = VexAuthInfo.find_by(vex_id: vex_id)
        log("vex_info already exists for #{vex_id}")
        if (vex_info.email != result[:email].downcase)
          log("update auth info email")
          log("new user creation #{result[:email].downcase}")
          vex_info.email = result[:email].downcase
          vex_info.save
        end
        if licenses = user_json["data"]["licenses"]
          log("going to process licenses #{licenses}")
          licenses.each do |license|
            log("processing license #{license["key"]}")
            if vex_info.licenses.find_by(license: license["key"])
              log("license already exists")
            else
              log("adding license #{license["key"]}")
              info_license = vex_info.licenses.create(vex_id: vex_id, license: license["key"], expires_at: license["expires_at"], platform: license["platform"])
              info_license.save
            end
          end
        end
        vex_info.save
      else
        log("new user creation #{result[:email].downcase}")
        vex_info = VexAuthInfo.new(vex_id: vex_id, email: result[:email].downcase)
        vex_info.save
        log("vex_info created for #{vex_id}")
        if licenses = user_json["data"]["licenses"]
          log("going to process licenses #{licenses}")
          licenses.each do |license|
            log("adding license #{license["key"]}")
            info_license = vex_info.licenses.create(vex_id: vex_id, license: license["key"], expires_at: license["expires_at"], platform: license["platform"])
            info_license.save
          end
        end
        vex_info.save
      end

      result
    else
      nil
    end
  end

  def primary_email_verified?(auth)
    return true if SiteSetting.oauth2_email_verified
    verified = auth['info']['email_verified']
    verified = true if verified == "true"
    verified = false if verified == "false"
    verified
  end

  def always_update_user_email?
    SiteSetting.oauth2_overrides_email
  end

  def after_authenticate(auth, existing_account: nil)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\nuid: #{auth['uid']}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

    if SiteSetting.oauth2_fetch_user_details?
      if fetched_user_details = fetch_user_details(auth['credentials']['token'], auth['uid'])
        auth['uid'] = fetched_user_details[:user_id] if fetched_user_details[:user_id]
        auth['info']['nickname'] = fetched_user_details[:username] if fetched_user_details[:username]
        auth['info']['image'] = fetched_user_details[:avatar] if fetched_user_details[:avatar]
        ['name', 'email', 'email_verified'].each do |property|
          auth['info'][property] = fetched_user_details[property.to_sym] if fetched_user_details[property.to_sym]
        end

        DiscoursePluginRegistry.oauth2_basic_additional_json_paths.each do |detail|
          auth['extra'][detail] = fetched_user_details["extra:#{detail}"]
        end
      else
        result = Auth::Result.new
        result.failed = true
        result.failed_reason = I18n.t("login.authenticator_error_fetch_user_details")
        return result
      end
    end

    output = super(auth, existing_account: existing_account)

    # we store the list of licensed platforms here
    active_licenses = Array.new

    # apply the license grops to the user...
    if output.user
      ::OAuth2BasicAuthenticator.process_user_license(output.user)
    else
      log("no user found?")
    end

    output
  end

  def after_create_account(user, auth)
    log("after_create_account")
    super(user, auth)
  end

  def enabled?
    SiteSetting.oauth2_enabled
  end

  def self.glog(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  DiscourseEvent.on(:user_logged_in) do |user|
    if user
      ::OAuth2BasicAuthenticator.process_user_license(user)
    end
  end

  DiscourseEvent.on(:user_seen) do |user|
    if user
      groups = user.groups.map { |group| group.name}
      if !groups.include?('vex_general')
        ::OAuth2BasicAuthenticator.process_user_license(user)
      end
    end
  end

  def self.process_user_license(user)
    if vex_info = VexAuthInfo.find_by(email: user.email)
      # we store the list of licensed platforms here
      active_licenses = Array.new
      all_access = false
      trial_access = false
      is_staff = false

      # find the list of active licenses
      if vex_info.licenses
        glog("checking user licenses")
        vex_info.licenses.each do |license|
          if license.is_valid?
            if license["platform"] == "3 Day Trial"
              trial_access = true
            elsif license["platform"] == "All Access"
              all_access = true
            elsif license["platform"] == "Staff"
              is_staff = true
            else
              active_licenses.push(license["platform"])
            end
          end
        end
      else
        glog("no licenses to check")
      end

      glog("found active licenses #{active_licenses}")

      has_active_license = active_licenses.length > 0

      license_general_group = "vex_general"
      license_groups = ["general", "123", "go", "iq", "v5", "vr", "viqc", "vrc", "3_day_trial"].select {|elem| elem != nil }.map { |str| "vex_#{str.downcase}"}

      if (all_access)
        active_license_groups = license_groups
      elsif (has_active_license)
        active_licenses.push("general")
        active_license_groups = active_licenses.map { |str| "vex_#{str.downcase}"}
      else
        active_license_groups = []
      end

      # apply the license grops to the user...
      glog("removing license groups")
      user.groups.map do |group|
        if (license_groups.include?(group.name) && !active_license_groups.include?(group.name))
          glog("removing #{user.name} from group #{group.name}")
          group.remove(user)
        end
      end

      glog("removing 3 day trial groups")
      user.groups.map do |group|
        if (group.name == 'vex_3_day_trial')
          glog("removing #{user.name} from group #{group.name}")
          group.remove(user)
        end
      end

      if (trial_access)
        Group.where("name LIKE 'vex_3_day_trial'").each do |group|
          glog("adding #{user.name} to group #{group.name}")
          group.add(user)
        end
      end

      glog("removing staff and moderators groups")
      user.groups.map do |group|
        if (group.name == 'moderators' || group.name == 'staff')
          glog("removing #{user.name} from group #{group.name}")
          group.remove(user)
        end
      end

      if (is_staff)
        Group.where("name LIKE 'moderators' or name LIKE 'staff'").each do |group|
          glog("adding #{user.name} to group #{group.name}")
          group.add(user)
        end
      end

      glog("adding licensed groups")
      missing_groups = license_groups.map(&:clone)
      Group.where("name LIKE 'vex_%'").each do |group|
        # log("where like found #{group.name}")
        if (active_license_groups.include?(group.name))
          glog("adding #{user.name} to group #{group.name}")
          group.add(user)
        end
        missing_groups = missing_groups - [group.name]
      end

      glog("adding missing groups #{missing_groups}")
      missing_groups.each do |group_name|
        glog("creating new group #{group_name}")
        group = Group.new(name: group_name)
        group.save
        if (active_license_groups.include?(group.name))
          glog("adding #{user.name} to group #{group.name}")
          group.add(user)
        end
      end
    else
      glog("unable to find auth info? #{user.email}")
    end
  end

end

auth_provider title_setting: "oauth2_button_title",
              authenticator: OAuth2BasicAuthenticator.new

load File.expand_path("../lib/validators/oauth2_basic/oauth2_fetch_user_details_validator.rb", __FILE__)
