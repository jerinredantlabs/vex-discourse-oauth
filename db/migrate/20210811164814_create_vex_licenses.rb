class CreateVexLicenses < ActiveRecord::Migration[6.1]
  def change
    create_table :vex_licenses, force: true do |t|
      t.bigint :vex_id
      t.string :key
      t.string :expires_at
      t.string :platform

      t.timestamps
      t.belongs_to :vex_auth_info, class_name: "VexAuthInfo", foreign_key: "vex_id", primary_key: "vex_id"
    end
  end
end
