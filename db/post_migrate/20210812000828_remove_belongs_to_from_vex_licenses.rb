class RemoveBelongsToFromVexLicenses < ActiveRecord::Migration[6.1]
  def change
    remove_belongs_to :vex_licenses, :vex_auth_info
  end
end
