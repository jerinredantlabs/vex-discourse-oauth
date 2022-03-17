class ImproveVexLicenses < ActiveRecord::Migration[6.1]
  def change
    add_index :vex_licenses, :license, unique: true, if_not_exists: true
    add_index :vex_auth_infos, :vex_id, unique: true, if_not_exists: true
  end
end
