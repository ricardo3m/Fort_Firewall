#ifndef PROGNETWORKPAGE_H
#define PROGNETWORKPAGE_H

#include "progbasepage.h"

class QComboBox;
class QLabel;

class LineEdit;
class ZonesSelector;

class ProgNetworkPage : public ProgBasePage
{
    Q_OBJECT

public:
    explicit ProgNetworkPage(ProgramEditController *ctrl = nullptr, QWidget *parent = nullptr);

    quint16 currentRuleId() const { return m_currentRuleId; }
    void setCurrentRuleId(quint16 ruleId = 0) { m_currentRuleId = ruleId; }

public slots:
    void fillApp(App &app) const override;

protected slots:
    void onPageInitialize(const App &app) override;

    void onRetranslateUi() override;

private:
    void initializeRuleField(bool isSingleSelection);

    void setupUi();
    QLayout *setupZonesRuleLayout();
    QLayout *setupRuleLayout();
    QLayout *setupIfaceLayout();

    void reloadIfaceCombo(quint64 selectedLuid);
    quint64 currentIfaceLuid() const;

    void selectRuleDialog();
    void editRuleDialog(int ruleId);

private:
    quint16 m_currentRuleId = 0;

    QCheckBox *m_cbLanOnly = nullptr;
    ZonesSelector *m_btZones = nullptr;
    LineEdit *m_editRuleName = nullptr;
    QToolButton *m_btSelectRule = nullptr;
    QLabel *m_labelIface = nullptr;
    QComboBox *m_comboIface = nullptr;
};

#endif // PROGNETWORKPAGE_H
