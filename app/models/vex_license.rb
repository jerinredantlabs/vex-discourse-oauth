class VexLicense < ActiveRecord::Base
  belongs_to :auth_info, class_name: "VexAuthInfo", foreign_key: "vex_id", primary_key: "vex_id"

  def is_valid?
    now = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S")
    return self.expires_at.gsub(".000000Z", "") >= now
  end
end
