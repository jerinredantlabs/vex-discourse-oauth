class VexAuthInfo < ActiveRecord::Base
  has_many :licenses, class_name: "VexLicense", foreign_key: "vex_id", primary_key: "vex_id", dependent: :destroy
end
